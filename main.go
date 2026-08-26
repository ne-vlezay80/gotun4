//go:build linux

// L3/L2 туннель поверх TCP с кадрированием «2 байта big-endian длины».
//
// ⚠️ Трафик НЕ шифруется и НЕ аутентифицируется: любой, кто откроет TCP-соединение
// с сервером, сможет инжектировать произвольные IP-пакеты в TUN и читать исходящий
// трафик. Только для доверенных сетей/экспериментов либо под WireGuard/mTLS сверху.
//
// Пакеты, приходящие в TUN при отсутствии активного соединения, отбрасываются.
//
// Настройка (пример):
//	sudo ip addr add 10.66.66.1/30 dev tun0 && sudo ip link set tun0 up  # сервер
//	sudo ip addr add 10.66.66.2/30 dev tun0 && sudo ip link set tun0 up  # клиент
//	+ маршруты на нужные подсети. MTU программа выставляет сама (флаг -mtu,
//	по умолчанию 1400 — компенсация оверхеда IP/TCP, чтобы не ломать PMTUD).
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

// Константы из заголовочных файлов Linux
const (
    TUNSETIFF   = 0x400454ca
    SIOCSIFMTU  = 0x8922
    IFF_TUN     = 0x0001
    IFF_TAP     = 0x0002
    IFF_NO_PI   = 0x1000
    IFF_PERSIST = 0x0800
)

// Лимит накладывает 2-байтовый префикс длины
const maxFrameSize = 65535

// ifReq повторяет struct ifreq ядра Linux: sizeof = 40 байт на LP64 (amd64/arm64).
type ifReq struct {
    Name  [16]byte
    Flags uint16
    _     [22]byte // добор до 40 байт: 16 (имя) + 24 (union, максимум — struct ifmap)
}

// ifReqMTU — та же структура, но с заполненным полем ifru_mtu (int).
type ifReqMTU struct {
    Name [16]byte
    MTU  int32
    _    [20]byte // итого 40 байт
}

// TcpConfig хранит настройки TCP
type TcpConfig struct {
    NoDelay    bool
    KeepAlive  bool
    RxBufferMB int
    TxBufferMB int
}

// SafeConn защищает доступ к текущему соединению.
// Инвариант: данные в TCP пишет единственная горутина (ниже в main).
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

// TryStore сохраняет c, если слот свободен; false — если уже занят.
func (s *SafeConn) TryStore(c net.Conn) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.conn != nil {
        return false
    }
    s.conn = c
    return true
}

// ClearIfCurrent сбрасывает слот, только если там ещё лежит old
// (защита от гонки при замене соединения на новое).
func (s *SafeConn) ClearIfCurrent(old net.Conn) {
    s.mu.Lock()
    if s.conn == old {
        s.conn = nil
    }
    s.mu.Unlock()
}

// backoff — экспоненциальная задержка переподключения с потолком.
type backoff struct {
    d time.Duration
}

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
    mtu := flag.Int("mtu", 1400, "MTU интерфейса (компенсирует оверхед IP/TCP; <=0 — не менять)")
    persist := flag.Bool("persist", true, "Оставлять интерфейс после завершения процесса (IFF_PERSIST)")

    tcpnodelay := flag.Bool("nodelay", true, "Управление флагом TCP_NODELAY")
    tcpkeepalive := flag.Bool("keepalive", true, "Управление флагом TCP_KEEPALIVE")
    tcprxbuf := flag.Int("rxbuf", 32, "Размер входящего буфера TCP в МБ")
    tcptxbuf := flag.Int("txbuf", 32, "Размер исходящего буфера TCP в МБ")

    flag.Parse()

    cfg := &TcpConfig{
        NoDelay:    *tcpnodelay,
        KeepAlive:  *tcpkeepalive,
        RxBufferMB: *tcprxbuf,
        TxBufferMB: *tcptxbuf,
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

    state := &SafeConn{}

    // Поток отправки (TUN -> TCP). Один буфер на всё время жизни горутины.
    go func() {
        buf := make([]byte, maxFrameSize+2)
        for {
            n, err := ifce.Read(buf[2:])
            if err != nil {
                // Закрытый fd даёт *fs.PathError, оборачивающий os.ErrClosed,
                // поэтому нужно именно errors.Is, а не прямое сравнение.
                if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
                    return
                }
                // Пауза против горячего цикла при персистентной ошибке чтения.
                time.Sleep(10 * time.Millisecond)
                continue
            }
            if n == 0 {
                continue
            }
            if n > maxFrameSize {
                log.Printf("Кадр %d байт превышает лимит %d — отброшен", n, maxFrameSize)
                continue
            }

            conn := state.Get()
            if conn == nil {
                continue // нет активного TCP-соединения — пакет отбрасываем
            }

            binary.BigEndian.PutUint16(buf[:2], uint16(n))
            // (*net.TCPConn).Write либо записывает весь slice, либо возвращает
            // ошибку — цикл дозаписи не нужен.
            if _, err := conn.Write(buf[:2+n]); err != nil {
                log.Printf("Ошибка отправки в TCP: %v", err)
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

func runServer(ifce *os.File, addr string, state *SafeConn, cfg *TcpConfig) {
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

func runClient(ifce *os.File, addr string, state *SafeConn, cfg *TcpConfig) {
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

func handleConnection(ifce *os.File, tcpConn net.Conn, state *SafeConn, cfg *TcpConfig) {
    applyTCPSettings(tcpConn, cfg)

    // Буферизованный ридер: один recv() забирает сразу несколько кадров
    // вместо двух системных вызовов на пакет.
    const recvBufSize = 256 << 10
    r := bufio.NewReaderSize(tcpConn, recvBufSize)

    frame := make([]byte, maxFrameSize)
    var lenPrefix [2]byte

    defer func() {
        state.ClearIfCurrent(tcpConn)
        tcpConn.Close()
        log.Println("Обработчик соединения завершён")
    }()

    log.Println("Туннель запущен. Фрейминг 2 байта включен.")

    for {
        if _, err := io.ReadFull(r, lenPrefix[:]); err != nil {
            if !errors.Is(err, io.EOF) {
                log.Printf("Ошибка чтения длины кадра: %v", err)
            }
            break
        }

        frameLen := binary.BigEndian.Uint16(lenPrefix[:])
        // uint16 не бывает > 65535, поэтому осмысленная проверка — на ноль:
        // признак рассинхронизации протокола или кривого клиента.
        if frameLen == 0 {
            log.Println("Кадр нулевой длины — рассинхронизация протокола, разрыв соединения")
            break
        }

        if _, err := io.ReadFull(r, frame[:frameLen]); err != nil {
            log.Printf("Ошибка чтения тела кадра: %v", err)
            break
        }

        // Ядро принимает ровно один пакет за write() в TUN, а Go гарантирует
        // полную запись до ошибки.
        if _, err := ifce.Write(frame[:frameLen]); err != nil {
            log.Printf("Ошибка записи в TUN: %v", err)
            break
        }
    }
}

func applyTCPSettings(conn net.Conn, cfg *TcpConfig) {
    tcp, ok := conn.(*net.TCPConn)
    if !ok {
        return
    }
    tcp.SetNoDelay(cfg.NoDelay)
    tcp.SetKeepAlive(cfg.KeepAlive)
    if cfg.KeepAlive {
        // Фиксируем период явно, не полагаясь на дефолты рантайма.
        tcp.SetKeepAlivePeriod(15 * time.Second)
    }
    if mb := cfg.RxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetReadBuffer(mb)
    }
    if mb := cfg.TxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetWriteBuffer(mb)
    }
}
