//go:build linux

// L3/L2 туннель поверх TCP. Формат кадра v3:
//
//	[флаги u8][wireLen BE16][payLen BE16][wireLen байт данных]
//
//	wireLen — сколько байт идёт за заголовком (включая паддинг),
//	payLen  — сколько из них полезная нагрузка (всегда payLen <= wireLen).
//	флаги: 0x01 = FIRST, 0x02 = LAST; FIRST|LAST — целый пакет одним кадром.
//
// Режимы:
//
//	-chunk N (>0): фиксированные кадры. Каждый кадр несёт ровно N байт провода,
//	    короткие данные дополняются нулями, длинные пакеты режутся на куски.
//	    Значение -chunk на двух сторонах может отличаться.
//	-chunk 0:      кадры переменной длины (wireLen == payLen), без дробления.
//
// Ошибки TUN (интерфейс down/недоступен) НЕ разрывают TCP-соединение:
// пакеты отбрасываются, поток возобновляется автоматически при возврате
// интерфейса. Разрыв происходит только при ошибке самого TCP или нарушении
// протокола.
//
// ⚠️ Трафик НЕ шифруется и НЕ аутентифицируется. Только доверенные сети.
// ⚠️ Обе стороны должны быть собраны из одной версии программы.
package main

import (
    "bufio"
    "encoding/binary"
    "errors"
    "flag"
    "io"
    "log"
    "net"
    "os"
    "sync"
    "syscall"
    "time"
    "unsafe"
)

const (
    TUNSETIFF   = 0x400454ca
    SIOCSIFMTU  = 0x8922
    IFF_TUN     = 0x0001
    IFF_TAP     = 0x0002
    IFF_NO_PI   = 0x1000
    IFF_PERSIST = 0x0800

    flagFirst     = 0x01
    flagLast      = 0x02
    validFlags    = flagFirst | flagLast
    frameHdrSize  = 5             // флаги + wireLen + payLen
    maxPacketSize = 65535         // предел длины поля u16 и собранного пакета
    dropLogPeriod = 10*time.Second // троттлинг лога отбрасываний
)

// ifReq повторяет struct ifreq ядра Linux: sizeof = 40 байт на LP64.
type ifReq struct {
    Name  [16]byte
    Flags uint16
    _     [22]byte
}

type ifReqMTU struct {
    Name [16]byte
    MTU  int32
    _    [20]byte
}

type Config struct {
    NoDelay    bool
    KeepAlive  bool
    RxBufferMB int
    TxBufferMB int
    ChunkSize  int // >0 — фиксированные кадры размера N; <=0 — переменная длина
}

// SafeConn защищает доступ к текущему соединению.
type SafeConn struct {
    mu   sync.RWMutex
    conn net.Conn
}

func (s *SafeConn) Get() net.Conn {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.conn
}

func (s *SafeConn) Store(c net.Conn) {
    s.mu.Lock()
    s.conn = c
    s.mu.Unlock()
}

func (s *SafeConn) TryStore(c net.Conn) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.conn != nil {
        return false
    }
    s.conn = c
    return true
}

func (s *SafeConn) ClearIfCurrent(old net.Conn) {
    s.mu.Lock()
    if s.conn == old {
        s.conn = nil
    }
    s.mu.Unlock()
}

type backoff struct{ d time.Duration }

func (b *backoff) next() time.Duration {
    if b.d == 0 {
        b.d = 500 * time.Millisecond
    } else {
        b.d *= 2
        if b.d > 15*time.Second {
            b.d = 15 * time.Second
        }
    }
    return b.d
}

func (b *backoff) reset() { b.d = 0 }

func main() {
    mode := flag.String("mode", "client", "Режим работы: client или server")
    tunName := flag.String("tun", "tun0", "Имя TUN интерфейса")
    tunMode := flag.String("tunmode", "tun", "Режим TUN интерфейса (tun/tap)")
    addr := flag.String("addr", "127.0.0.1:1080", "Адрес подключения/прослушивания")
    mtu := flag.Int("mtu", 1400, "MTU интерфейса (<=0 — не менять)")
    persist := flag.Bool("persist", false, "Оставлять интерфейс после выхода (IFF_PERSIST)")
    chunk := flag.Int("chunk", 1400, "Фиксированный размер кадра: короткие пакеты добиваются до N, длинные режутся (<=(0) — переменная длина)")

    tcpnodelay := flag.Bool("nodelay", true, "Управление флагом TCP_NODELAY")
    tcpkeepalive := flag.Bool("keepalive", true, "Управление флагом TCP_KEEPALIVE")
    tcprxbuf := flag.Int("rxbuf", 32, "Входящий буфер TCP в МБ")
    tcptxbuf := flag.Int("txbuf", 32, "Исходящий буфер TCP в МБ")

    flag.Parse()

    cfg := &Config{
        NoDelay:    *tcpnodelay,
        KeepAlive:  *tcpkeepalive,
        RxBufferMB: *tcprxbuf,
        TxBufferMB: *tcptxbuf,
        ChunkSize:  *chunk,
    }
    if cfg.ChunkSize > maxPacketSize {
        log.Printf("-chunk %d больше максимума (%d), ограничен", cfg.ChunkSize, maxPacketSize)
        cfg.ChunkSize = maxPacketSize
    }

    ifce, err := openTun(*tunName, *tunMode == "tap", *persist)
    if err != nil {
        log.Fatalf("Ошибка создания TUN: %v", err)
    }
    defer ifce.Close()

    if *mtu > 0 {
        if err := setInterfaceMTU(*tunName, *mtu); err != nil {
            log.Printf("Предупреждение: не удалось выставить MTU=%d у %s: %v", *mtu, *tunName, err)
        } else {
            log.Printf("MTU интерфейса %s установлен в %d", *tunName, *mtu)
        }
    }

    if cfg.ChunkSize > 0 {
        log.Printf("Кадры фиксированной длины: %d байт нагрузки (+%d заголовок)", cfg.ChunkSize, frameHdrSize)
    } else {
        log.Println("Кадры переменной длины, без дробления и паддинга")
    }

    state := &SafeConn{}

    // Поток отправки (TUN -> TCP).
    go func() {
        buf := make([]byte, frameHdrSize+maxPacketSize)
        for {
            n, err := ifce.Read(buf[frameHdrSize:])
            if err != nil {
                // Закрытый fd даёт *fs.PathError вокруг os.ErrClosed — нужен errors.Is.
                if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
                    return
                }
                // Интерфейс недоступен: пауза против горячего цикла,
                // TCP-соединение при этом намеренно не трогаем.
                time.Sleep(10 * time.Millisecond)
                continue
            }
            if n == 0 {
                continue
            }
            if n > maxPacketSize {
                log.Printf("Кадр %d байт превышает максимум %d — отброшен (увеличьте -chunk)", n, maxPacketSize)
                continue
            }

            conn := state.Get()
            if conn == nil {
                continue // нет активного соединения — пакет отбрасываем
            }

            if !emitFrames(conn, buf, n, cfg.ChunkSize) {
                // Соединение рвём только при ошибке самого TCP.
                state.ClearIfCurrent(conn)
                conn.Close()
            }
        }
    }()

    switch *mode {
    case "server":
        runServer(ifce, *addr, state, cfg)
    case "client":
        runClient(ifce, *addr, state, cfg)
    default:
        log.Fatal("Неизвестный режим: ", *mode)
    }
}

// emitFrames пишет пакет длиной n (лежащий в buf с offset frameHdrSize) серией
// кадров [флаги][wireLen][payLen][данные].
//
// chunk > 0: каждый кадр занимает на проводе ровно chunk байт нагрузки;
// область паддинга каждый раз очищается, чтобы в канал не утекали остатки
// предыдущих пакетов. Последний кусок тоже добивается до полного размера.
// chunk <= 0: wireLen == payLen, кадры переменной длины без дробления.
//
// Первый кусок отправляется одним Write без копирования (уже лежит за заголовком),
// последующие сдвигаются copy() вперёд (copy безопасна для перекрывающихся областей).
func emitFrames(conn net.Conn, buf []byte, n, chunk int) bool {
    fixed := chunk > 0
    for off := 0; off < n; {
        seg := n - off
        if fixed && seg > chunk {
            seg = chunk
        }
        wireLen := seg
        if fixed {
            wireLen = chunk
        }

        f := byte(0)
        if off == 0 {
            f |= flagFirst
        }
        if off+seg == n {
            f |= flagLast
        }
        buf[0] = f
        binary.BigEndian.PutUint16(buf[1:3], uint16(wireLen))
        binary.BigEndian.PutUint16(buf[3:5], uint16(seg))

        payload := buf[frameHdrSize : frameHdrSize+seg]
        if off > 0 {
            copy(payload, buf[frameHdrSize+off:frameHdrSize+off+seg])
        }
        if pad := buf[frameHdrSize+seg : frameHdrSize+wireLen]; len(pad) > 0 {
            clear(pad) // в канале только нули, никаких остатков чужих пакетов
        }

        if _, err := conn.Write(buf[:frameHdrSize+wireLen]); err != nil {
            log.Printf("Ошибка отправки в TCP: %v", err)
            return false
        }
        off += seg
    }
    return true
}

func openTun(name string, isTAP bool, wantPersist bool) (*os.File, error) {
    fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
    if err != nil {
        return nil, err
    }

    var flags uint16 = IFF_NO_PI
    if isTAP {
        flags |= IFF_TAP
    } else {
        flags |= IFF_TUN
    }
    if wantPersist {
        flags |= IFF_PERSIST
    }

    var ifr ifReq
    copy(ifr.Name[:], name)
    ifr.Flags = flags

    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(fd),
        uintptr(TUNSETIFF),
        uintptr(unsafe.Pointer(&ifr)),
    )
    if errno != 0 {
        syscall.Close(fd)
        return nil, errno
    }

    kind := "TUN"
    if isTAP {
        kind = "TAP"
    }
    extra := ""
    if wantPersist {
        extra = " (persist)"
    }
    log.Printf("Открыт %s-интерфейс %q%s", kind, name, extra)

    return os.NewFile(uintptr(fd), kind+":"+name), nil
}

func setInterfaceMTU(name string, mtu int) error {
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
    if err != nil {
        return err
    }
    defer syscall.Close(fd)

    var ifr ifReqMTU
    copy(ifr.Name[:], name)
    ifr.MTU = int32(mtu)

    _, _, errno := syscall.Syscall(
        syscall.SYS_IOCTL,
        uintptr(fd),
        uintptr(SIOCSIFMTU),
        uintptr(unsafe.Pointer(&ifr)),
    )
    if errno != 0 {
        return errno
    }
    return nil
}

func runServer(ifce *os.File, addr string, state *SafeConn, cfg *Config) {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("Ошибка запуска сервера: %v", err)
    }
    defer listener.Close()

    log.Printf("Сервер ждёт соединений на %s...", addr)

    for {
        tcpConn, err := listener.Accept()
        if err != nil {
            log.Printf("Ошибка принятия соединения: %v", err)
            time.Sleep(1 * time.Second)
            continue
        }

        remote := tcpConn.RemoteAddr()
        if !state.TryStore(tcpConn) {
            log.Printf("Отклонено подключение от %s: сервер уже занят другим клиентом", remote)
            tcpConn.Close()
            continue
        }

        log.Printf("Клиент успешно подключен: %s", remote)
        go handleConnection(ifce, tcpConn, state, cfg)
    }
}

func runClient(ifce *os.File, addr string, state *SafeConn, cfg *Config) {
    bo := backoff{}
    for {
        log.Printf("Клиент подключается к %s...", addr)
        tcpConn, err := net.Dial("tcp", addr)
        if err != nil {
            log.Printf("Ошибка подключения: %v", err)
            time.Sleep(bo.next())
            continue
        }
        bo.reset()

        state.Store(tcpConn)
        handleConnection(ifce, tcpConn, state, cfg)

        log.Println("Соединение разорвано, переподключение...")
        time.Sleep(bo.next())
    }
}

// Состояния сборщика пакетов.
const (
    stIdle = iota // строго ждём FIRST
    stAssemble    // копим куски до LAST
)

func handleConnection(ifce *os.File, tcpConn net.Conn, state *SafeConn, cfg *Config) {
    applyTCPSettings(tcpConn, cfg)

    const recvBufSize = 256 << 10
    r := bufio.NewReaderSize(tcpConn, recvBufSize)

    frame := make([]byte, maxPacketSize) // сюда читается нагрузка текущего кадра (вместе с паддингом)
    var acc []byte                       // ленивый аккумулятор для многокадровых пакетов
    var hdr [frameHdrSize]byte
    mode := stIdle

    // Троттлинг лога: при выключенном интерфейсе и высоком pps без него
    // лог займёт весь вывод. Соединение при этих ошибках сознательно живёт дальше.
    var lastDrop time.Time
    writeTun := func(p []byte) {
        if _, err := ifce.Write(p); err != nil && time.Since(lastDrop) >= dropLogPeriod {
            lastDrop = time.Now()
            log.Printf("Пакет (%d байт) отброшен: ошибка записи в TUN: %v (соединение сохранено)", len(p), err)
        }
    }

    defer func() {
        state.ClearIfCurrent(tcpConn)
        tcpConn.Close()
        log.Println("Обработчик соединения завершён")
    }()

    log.Printf("Туннель запущен. Кадры: [флаги u8][wireLen BE16][payLen BE16][данные+паддинг].")

readLoop:
    for {
        if _, err := io.ReadFull(r, hdr[:]); err != nil {
            if !errors.Is(err, io.EOF) {
                log.Printf("Ошибка чтения заголовка: %v", err)
            }
            break
        }
        flags := hdr[0]
        wireLen := int(binary.BigEndian.Uint16(hdr[1:3]))
        payLen := int(binary.BigEndian.Uint16(hdr[3:5]))

        // Валидация. Нарушение формата = рассинхронизация, лечится только
        // переподключением. Эти проверки стоят вне switch, поэтому голый
        // break здесь корректно покидает внешний цикл.
        if flags&^validFlags != 0 {
            log.Printf("Недопустимые биты флагов %#02x — разрыв", flags)
            break
        }
        if wireLen == 0 || payLen == 0 || payLen > wireLen {
            log.Printf("Некорректные длины (wire=%d, payload=%d) — рассинхронизация, разрыв", wireLen, payLen)
            break
        }

        if _, err := io.ReadFull(r, frame[:wireLen]); err != nil {
            log.Printf("Ошибка чтения тела кадра: %v", err)
            break
        }
        payload := frame[:payLen] // паддинг в.tail отсекается самим payLen

        switch mode {
        case stIdle:
            if flags&flagFirst == 0 {
                log.Printf("Кадр без FIRST в состоянии IDLE (len=%d, flags=%#02x) — разрыв", payLen, flags)
                break readLoop // метка обязательна: внутри switch голый break прервал бы только switch
            }

            if flags&flagLast != 0 {
                // Быстрый путь: целый пакет одним кадром, без сборки.
                writeTun(payload)
                continue
            }

            // Первый кусок составного пакета — начинаем накопление.
            if acc == nil {
                acc = make([]byte, 0, maxPacketSize)
            }
            acc = acc[:payLen]
            copy(acc, payload)
            mode = stAssemble

        case stAssemble:
            if flags&flagFirst != 0 {
                log.Println("Новый FIRST посреди незавершённого пакета — разрыв")
                return
            }
            base := len(acc)
            if base+payLen > maxPacketSize {
                log.Printf("Собранный пакет превысил лимит %d байт — разрыв", maxPacketSize)
                return
            }
            acc = acc[:base+payLen]
            copy(acc[base:], payload)

            if flags&flagLast != 0 {
                writeTun(acc)
                mode = stIdle
            }
        }
    }
}

func applyTCPSettings(conn net.Conn, cfg *Config) {
    tcp, ok := conn.(*net.TCPConn)
    if !ok {
        return
    }
    tcp.SetNoDelay(cfg.NoDelay)
    tcp.SetKeepAlive(cfg.KeepAlive)
    if cfg.KeepAlive {
        tcp.SetKeepAlivePeriod(15 * time.Second)
    }
    if mb := cfg.RxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetReadBuffer(mb)
    }
    if mb := cfg.TxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetWriteBuffer(mb)
    }
}
