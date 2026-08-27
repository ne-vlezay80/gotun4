//go:build linux

// L3/L2 туннель поверх TCP.
//
// Формат кадра:
//
//	[флаги u8][длина BE16][нагрузка]
//
//	флаг 0x01 = FIRST, 0x02 = LAST; целому пакету в одном куске соответствуют оба.
//
// Флаг -chunk N включает дробление исходящих пакетов на куски ≤ N:
// первый кусок помечается FIRST, последний LAST. Принимающая сторона
// собирает пакет до записи в TUN, поэтому её -chunk может отличаться.
// Максимальный размер собранного пакета и одного куска — 65535 байт.
//
// ⚠️ Трафик НЕ шифруется и НЕ аутентифицируется. Только доверенные сети.
// ⚠️ Обе стороны должны быть собраны из одной версии программы.
//
// Настройка:
//	sudo ip addr add 10.66.66.1/30 dev tun0 && sudo ip link set tun0 up
//	MTU выставляется автоматически (-mtu, по умолчанию 1400).
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
    TUNSETIFF  = 0x400454ca
    SIOCSIFMTU = 0x8922
    IFF_TUN    = 0x0001
    IFF_TAP    = 0x0002
    IFF_NO_PI  = 0x1000
    IFF_PERSIST = 0x0800 

    flagFirst     = 0x01
    flagLast      = 0x02
    validFlags    = flagFirst | flagLast
    chunkHdrSize  = 3
    maxPacketSize = 65535 // предел длины куска (u16) и собранного пакета
)

// ifReq повторяет struct ifreq ядра Linux: sizeof = 40 байт на LP64 (amd64/arm64).
type ifReq struct {
    Name  [16]byte
    Flags uint16
    _     [22]byte
}

// ifReqMTU — та же структура с заполненным полем ifru_mtu (int).
type ifReqMTU struct {
    Name [16]byte
    MTU  int32
    _    [20]byte
}

// Config — все настройки туннеля.
type Config struct {
    NoDelay    bool
    KeepAlive  bool
    RxBufferMB int
    TxBufferMB int
    ChunkSize  int // ≤0 — не дробить; иначе куски ≤ ChunkSize (сжимается до 65535)
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
    chunk := flag.Int("chunk", 1400, "Размер куска при дроблении пакетов, байт (<=0 — без дробления)")

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
    switch {
    case cfg.ChunkSize > maxPacketSize:
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
        log.Printf("Дробление пакетов включено: куски до %d байт", cfg.ChunkSize)
    } else {
        log.Printf("Дробление выключено: пакет = один кадр")
    }

    state := &SafeConn{}

    // Поток отправки (TUN -> TCP).
    go func() {
        buf := make([]byte, chunkHdrSize+maxPacketSize) // + место под 3-байтовый заголовок
        for {
            n, err := ifce.Read(buf[chunkHdrSize:])
            if err != nil {
                // Закрытый fd даёт *fs.PathError вокруг os.ErrClosed — нужно errors.Is.
                if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
                    return
                }
                time.Sleep(10 * time.Millisecond) // против горячего цикла
                continue
            }
            if n == 0 {
                continue
            }

            conn := state.Get()
            if conn == nil {
                continue // нет активного соединения — пакет отбрасываем
            }

            if !emitChunks(conn, buf, n, cfg.effectiveChunk()) {
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

// effectiveChunk возвращает рабочий лимит куска; <=0 означает «не дробить»,
// что эквивалентно лимиту maxPacketSize.
func (c *Config) effectiveChunk() int {
    if c.ChunkSize <= 0 || c.ChunkSize > maxPacketSize {
        return maxPacketSize
    }
    return c.ChunkSize
}

// emitChunks пишет пакет длиной n из buf как кадры с заголовками
// [флаги][длина BE16], соблюдая FIRST/LAST. Возвращает false при ошибке записи.
//
// Буфер устроен так: пакет лежит с offset 3, поэтому первый кусок уже
// расположен подряд с заголовком — он уходит одним Write без копирования.
// Последующие куски сдвигаются copy() в начало области нагрузки
// (copy безопасно работает с перекрывающимися областями).
func emitChunks(conn net.Conn, buf []byte, n, chunkLimit int) bool {
    var (
        off int
        f   byte
    )
    for off < n {
        seg := chunkLimit
        if rest := n - off; rest < seg {
            seg = rest
        }
        payload := buf[chunkHdrSize : chunkHdrSize+seg]
        if off > 0 {
            copy(payload, buf[chunkHdrSize+off:chunkHdrSize+off+seg])
        }

        f = 0
        if off == 0 {
            f |= flagFirst
        }
        if off+seg == n {
            f |= flagLast
        }
        buf[0] = f
        binary.BigEndian.PutUint16(buf[1:3], uint16(seg))

        if _, err := conn.Write(buf[:chunkHdrSize+seg]); err != nil {
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

// setInterfaceMTU выставляет MTU интерфейса через SIOCSIFMTU.
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

// Состояние сборщика пакетов.
const (
    stIdle     = iota // ждём FIRST
    stAssemble        // копим куски до LAST
)

func handleConnection(ifce *os.File, tcpConn net.Conn, state *SafeConn, cfg *Config) {
    applyTCPSettings(tcpConn, cfg)

    const recvBufSize = 256 << 10
    r := bufio.NewReaderSize(tcpConn, recvBufSize)

    frame := make([]byte, maxPacketSize)     // буфер для одиночных кусков
    var acc []byte                            // ленивый аккумулятор для многокусковых пакетов
    var hdr [chunkHdrSize]byte
    mode := stIdle

    defer func() {
        state.ClearIfCurrent(tcpConn)
        tcpConn.Close()
        log.Println("Обработчик соединения завершён")
    }()

    writeToTun := func(p []byte) bool {
        if _, err := ifce.Write(p); err != nil {
            log.Printf("Ошибка записи в TUN: %v", err)
            return false
        }
        return true
    }

    log.Println("Туннель запущен. Фрейминг: [флаги u8][длина BE16][нагрузка].")
    readLoop:
    for {
        if _, err := io.ReadFull(r, hdr[:]); err != nil {
            if !errors.Is(err, io.EOF) {
                log.Printf("Ошибка чтения заголовка: %v", err)
            }
            break
        }
        flags := hdr[0]
        flen := int(binary.BigEndian.Uint16(hdr[1:3]))

        if flen == 0 {
            log.Println("Кадр нулевой длины — рассинхронизация протокола, разрыв")
            break
        }
        if flags &^ validFlags != 0 {
            log.Printf("Недопустимые биты флагов %#02x — рассинхронизация или чужой клиент, разрыв", flags)
            break
        }

        switch mode {
        case stIdle:
            if flags&flagFirst == 0 {
                log.Printf("Кусок без FIRST в состоянии IDLE (len=%d, flags=%#02x) — разрыв", flen, flags)
                break readLoop
            }

            if flags&flagLast != 0 {
                // Быстрый путь: целый пакет одним куском, без сборки.
                if _, err := io.ReadFull(r, frame[:flen]); err != nil {
                    log.Printf("Ошибка чтения тела пакета: %v", err)
                    return
                }
                if !writeToTun(frame[:flen]) {
                    return
                }
                continue
            }

            // Первый кусок составного пакета — начинаем накопление.
            if acc == nil {
                acc = make([]byte, 0, maxPacketSize)
            }
            acc = acc[:0]
            acc = acc[:flen]
            if _, err := io.ReadFull(r, acc); err != nil {
                log.Printf("Ошибка чтения первого куска: %v", err)
                return
            }
            mode = stAssemble

        case stAssemble:
            if flags&flagFirst != 0 {
                log.Println("Новый FIRST посреди незавершённого пакета — разрыв")
                return
            }
            base := len(acc)
            if base+flen > maxPacketSize {
                log.Printf("Собранный пакет превысил лимит %d байт — разрыв", maxPacketSize)
                return
            }
            acc = acc[:base+flen]
            if _, err := io.ReadFull(r, acc[base:]); err != nil {
                log.Printf("Ошибка чтения куска: %v", err)
                return
            }

            if flags&flagLast != 0 {
                if !writeToTun(acc) {
                    return
                }
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
