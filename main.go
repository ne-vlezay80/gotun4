//go:build linux

// L3/L2 туннель поверх TCP. Формат кадра v3:
//
//	[флаги u8][wireLen BE16][payLen BE16][wireLen байт данных]
//
//	wireLen — сколько байт идёт за заголовком (полезные данные + паддинг),
//	payLen  — сколько из них реальные данные (payLen <= wireLen).
//	флаги: 0x01 = FIRST, 0x02 = LAST; FIRST|LAST — целый пакет одним кадром.
//
// Кадрирование (-chunk):
//	N  > 0: каждый кадр несёт ровно N байт провода; данные добиваются
//	        до N или режутся на куски. Стороны могут иметь разные N.
//	N <= 0: кадры переменной длины, без дробления.
//
// Шейпер (-delay/-jitter): задерживает выдачу каждого пакета (целиком,
// порядок кусков внутри пакета сохранён) на delay + равномерный джиттер
// [0, jitter). Применяется отдельно к каждому направлению, поэтому RTT
// вырастает примерно на 2*delay. Очередь шейпера ограничена по байтам
// (-shapebuf), переполнение = tail-drop.
//
// Паддинг (-padmode): чем заполняется область добивки в фиксированных
// кадрах — нулями или криптосткойкой псевдослучайностью (ChaCha8).
// Это маскировка slack-области, а НЕ шифрование: длины кадров и тайминги
// остаются открытыми.
//
// Многопроцессорность: рантайм Go сам использует все ядра; флаг -procs
// позволяет лишь явно ограничить параллелизм (GOMAXPROCS).
//
// Ошибки TUN (интерфейс down) НЕ разрывают TCP: пакеты молча дропаются,
// поток возобновляется автоматически. Разрыв — только ошибка TCP или
// нарушение протокола.
//
// ⚠️ Трафик НЕ шифруется и НЕ аутентифицируется. Только доверенные сети.
package main

import (
    "bufio"
    "container/heap"
    crand "crypto/rand"
    "encoding/binary"
    "errors"
    "flag"
    "io"
    "log"
    mrand "math/rand/v2"
    "net"
    "os"
    "runtime"
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
    frameHdrSize  = 5
    maxPacketSize = 65535
    dropLogPeriod = 10 * time.Second
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
    ChunkSize  int
    Delay      time.Duration
    Jitter     time.Duration
    ShapeBufMB int
    PadMode    string // "zero" | "random"
}

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

// ---- пул буферов под пакеты (используется шейпером и путём отправки) ----

var pktPool = sync.Pool{
    New: func() any { return make([]byte, frameHdrSize+maxPacketSize) },
}

func getPkt() []byte    { return pktPool.Get().([]byte) }
func putPkt(b []byte)   { pktPool.Put(b) }

// newPadFiller возвращает функцию заполнения области паддинга.
// Режиму random соответствует один экземпляр ChaCha8, засеянный из
// crypto/rand: он криптостойкий и при этом быстрый (~ГБ/с), так что
// стоимость сопоставима с memset и пригодна для каждого кадра.
// Экземпляр используется единственной горутиной-отправителем.
func newPadFiller(mode string) func([]byte) {
    switch mode {
    case "random":
        var seed [32]byte
        if _, err := crand.Read(seed[:]); err != nil {
            log.Fatalf("Критично: crypto/rand недоступен: %v", err)
        }
        rng := mrand.NewChaCha8(seed)
        return func(b []byte) {
            for len(b) > 0 {
                n, _ := rng.Read(b)
                if n <= 0 {
                    break
                }
                b = b[n:]
            }
        }
    default: // "zero"
        return func(b []byte) { clear(b) }
    }
}

// ---- шейпер: мин-куча по времени отправки + один таймер ----

type schedItem struct {
    at  time.Time
    pkt []byte // буфер из pktPool; владение переходит к out()
    n   int    // размер полезной части (для учёта очереди)
}

type schedQueue []schedItem

func (q schedQueue) Len() int           { return len(q) }
func (q schedQueue) Less(i, j int) bool { return q[i].at.Before(q[j].at) }
func (q schedQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *schedQueue) Push(x any)        { *q = append(*q, x.(schedItem)) }
func (q *schedQueue) Pop() any {
    old := *q
    it := old[len(old)-1]
    *q = old[:len(old)-1]
    return it
}

type shaper struct {
    delay, jitter time.Duration
    maxBytes      int
    out           func(pkt []byte, n int) // получает владение pkt, обязан вернуть его в пул

    mu      sync.Mutex
    q       schedQueue
    bytes   int
    wake    chan struct{}
    done    chan struct{}
    lastLog time.Time
}

func newShaper(delay, jitter time.Duration, maxBytes int, out func([]byte, int)) *shaper {
    if delay < 0 {
        delay = 0
    }
    if jitter < 0 {
        jitter = 0
    }
    s := &shaper{
        delay:    delay,
        jitter:   jitter,
        maxBytes: maxBytes,
        out:      out,
        wake:     make(chan struct{}, 1),
        done:     make(chan struct{}),
    }
    go s.run()
    return s
}

// Submit принимает владение pkt (буфер должен быть из pktPool).
// Никогда не блокирует: при переполнении — tail-drop пакета.
func (s *shaper) Submit(pkt []byte, n int) {
    at := time.Now().Add(s.delay)
    if s.jitter > 0 {
        at = at.Add(time.Duration(mrand.Int64N(int64(s.jitter))))
    }

    s.mu.Lock()
    if s.bytes+n > s.maxBytes {
        if time.Since(s.lastLog) >= dropLogPeriod {
            s.lastLog = time.Now()
            log.Printf("Шейпер: очередь переполнена (%d/%d байт), пакет %d байт отброшен (tail-drop)", s.bytes, s.maxBytes, n)
        }
        s.mu.Unlock()
        putPkt(pkt)
        return
    }
    s.bytes += n
    heap.Push(&s.q, schedItem{at: at, pkt: pkt, n: n})
    s.mu.Unlock()

    select {
    case s.wake <- struct{}{}:
    default:
    }
}

func (s *shaper) run() {
    var t *time.Timer
    defer func() {
        if t != nil {
            t.Stop()
        }
    }()
    defer s.drain()

    for {
        s.mu.Lock()
        if len(s.q) == 0 {
            s.mu.Unlock()
            select {
            case <-s.wake:
            case <-s.done:
                return
            }
            continue
        }
        next := s.q[0].at
        s.mu.Unlock()

        d := time.Until(next)
        if d < 0 {
            d = 0
        }

        if t == nil {
            t = time.NewTimer(d)
        } else {
            if !t.Stop() {
                select {
                case <-t.C:
                default:
                }
            }
            t.Reset(d)
        }

        select {
        case <-t.C:
            // подошёл срок головного элемента (или ложное пробуждение —
            // цикл ниже всё равно фильтрует по времени)
        case <-s.wake:
            // мог прийти элемент с более ранним сроком — пересчитаемся
        case <-s.done:
            return
        }

        now := time.Now()
        for {
            s.mu.Lock()
            if len(s.q) == 0 || s.q[0].at.After(now) {
                s.mu.Unlock()
                break
            }
            it := heap.Pop(&s.q).(schedItem)
            s.bytes -= it.n
            s.mu.Unlock()

            s.out(it.pkt, it.n)
        }
    }
}

func (s *shaper) drain() {
    s.mu.Lock()
    for _, it := range s.q {
        putPkt(it.pkt)
    }
    s.q = s.q[:0]
    s.bytes = 0
    s.mu.Unlock()
}

func (s *shaper) Close() { close(s.done) }

// ---------------------------- main ----------------------------

func main() {
    mode := flag.String("mode", "client", "Режим работы: client или server")
    tunName := flag.String("tun", "tun0", "Имя TUN интерфейса")
    tunMode := flag.String("tunmode", "tun", "Режим TUN интерфейса (tun/tap)")
    addr := flag.String("addr", "127.0.0.1:1080", "Адрес подключения/прослушивания")
    mtu := flag.Int("mtu", 1400, "MTU интерфейса (<=0 — не менять)")
    persist := flag.Bool("persist", false, "Оставлять интерфейс после выхода (IFF_PERSIST)")
    chunk := flag.Int("chunk", 1400, "Фиксированный размер кадра: добивка/нарезка до N (<=(0) — переменная длина)")

    delay := flag.Duration("delay", 0, "Базовая задержка НА НАПРАВЛЕНИЕ (RTT вырастет ~на 2x), например 50ms")
    jitter := flag.Duration("jitter", 0, "Случайная добавка 0..jitter на направление (uniform)")
    shapebuf := flag.Int("shapebuf", 16, "Лимит очереди шейпера в МБ на направление")
    padmode := flag.String("padmode", "zero", "Заполнитель паддинга фиксированных кадров: zero|random")
    procs := flag.Int("procs", 0, "Ограничить число ядер (GOMAXPROCS); 0 — решение рантайма")

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
        Delay:      *delay,
        Jitter:     *jitter,
        ShapeBufMB: *shapebuf,
        PadMode:    *padmode,
    }

    if cfg.ChunkSize > maxPacketSize {
        log.Printf("-chunk %d больше максимума (%d), ограничен", cfg.ChunkSize, maxPacketSize)
        cfg.ChunkSize = maxPacketSize
    }
    if cfg.PadMode != "zero" && cfg.PadMode != "random" {
        log.Printf("-padmode %q неизвестен, использую zero", cfg.PadMode)
        cfg.PadMode = "zero"
    }
    if cfg.ShapeBufMB <= 0 {
        log.Printf("-shapebuf %d некорректен, использую 16 МБ", cfg.ShapeBufMB)
        cfg.ShapeBufMB = 16
    }

    if *procs > 0 {
        prev := runtime.GOMAXPROCS(*procs)
        log.Printf("GOMAXPROCS: %d -> %d", prev, *procs)
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
        log.Printf("Кадры фиксированной длины: %d байт (+%d заголовок), паддинг: %s", cfg.ChunkSize, frameHdrSize, cfg.PadMode)
    } else {
        log.Println("Кадры переменной длины, без дробления")
    }
    if cfg.Delay > 0 || cfg.Jitter > 0 {
        log.Printf("Шейпер включён: delay=%s jitter=%s (на каждое направление, лимит очереди %d МБ)", cfg.Delay, cfg.Jitter, cfg.ShapeBufMB)
    }

    state := &SafeConn{}
    padFill := newPadFiller(cfg.PadMode)

    // Единая точка отправки в TCP (вызывается ТОЛЬКО из одной горутины:
    // либо цикл чтения TUN, либо диспетчер шейпера — одновременно никогда).
    sendOverTCP := func(conn net.Conn, pkt []byte, n int) {
        ok := emitFrames(conn, pkt, n, cfg.ChunkSize, padFill)
        putPkt(pkt)
        if !ok {
            state.ClearIfCurrent(conn)
            conn.Close()
        }
    }

    // Исходящий шейпер. nil = выключен, прямой путь без копий.
    shapeBytes := cfg.ShapeBufMB << 20
    var txShape *shaper
    if cfg.Delay > 0 || cfg.Jitter > 0 {
        txShape = newShaper(cfg.Delay, cfg.Jitter, shapeBytes, func(pkt []byte, n int) {
            c := state.Get()
            if c == nil {
                putPkt(pkt)
                return
            }
            sendOverTCP(c, pkt, n)
        })
    }

    // Поток отправки (TUN -> шейпер -> TCP).
    go func() {
        buf := make([]byte, frameHdrSize+maxPacketSize)
        for {
            n, err := ifce.Read(buf[frameHdrSize:])
            if err != nil {
                // Закрытый fd даёт *fs.PathError вокруг os.ErrClosed.
                if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
                    return
                }
                time.Sleep(10 * time.Millisecond) // против горячего цикла
                continue
            }
            if n == 0 {
                continue
            }
            if n > maxPacketSize {
                log.Printf("Пакет %d байт превышает максимум %d — отброшен", n, maxPacketSize)
                continue
            }

            conn := state.Get()
            if conn == nil {
                continue // нет активного соединения — пакет отбрасываем
            }

            if txShape == nil {
                // Быстрый путь: пакет уже лежит за заголовком, без копий.
                if !emitFrames(conn, buf, n, cfg.ChunkSize, padFill) {
                    state.ClearIfCurrent(conn)
                    conn.Close()
                }
                continue
            }

            // Копия в пул: buf переиспользуется, а пакет полежит в очереди.
            pkt := getPkt()
            copy(pkt[frameHdrSize:frameHdrSize+n], buf[frameHdrSize:frameHdrSize+n])
            txShape.Submit(pkt, n)
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

// emitFrames пишет пакет длиной n (payload лежит в buf с offset frameHdrSize)
// серией кадров [флаги][wireLen][payLen][данные+паддинг].
//
// chunk > 0: каждый кадр занимает ровно chunk байт нагрузки; область паддинга
// каждый раз заполняется через fill (нули или случайные байты), поэтому
// содержимое предыдущих пакетов физически не может попасть в канал.
// Последний кусок тоже добивается до полного размера.
// chunk <= 0: wireLen == payLen, без дробления и без паддинга.
func emitFrames(conn net.Conn, buf []byte, n, chunk int, fill func([]byte)) bool {
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
            fill(pad)
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
    stIdle     = iota // строго ждём FIRST
    stAssemble        // копим куски до LAST
)

func handleConnection(ifce *os.File, tcpConn net.Conn, state *SafeConn, cfg *Config) {
    applyTCPSettings(tcpConn, cfg)

    const recvBufSize = 256 << 10
    r := bufio.NewReaderSize(tcpConn, recvBufSize)

    frame := make([]byte, maxPacketSize)
    var acc []byte
    var hdr [frameHdrSize]byte
    mode := stIdle

    // Молчаливое дропание при ошибке записи в TUN (интерфейс down),
    // лог не чаще раза в dropLogPeriod.
    var lastDrop time.Time
    writeTun := func(p []byte) {
        if _, err := ifce.Write(p); err != nil && time.Since(lastDrop) >= dropLogPeriod {
            lastDrop = time.Now()
            log.Printf("Пакет (%d байт) отброшен: ошибка записи в TUN: %v (соединение сохранено)", len(p), err)
        }
    }

    // Входной шейпер: после полной сборки пакет ждёт своего срока и
    // внедряется в TUN. nil = прямой путь.
    var rxShape *shaper
    if cfg.Delay > 0 || cfg.Jitter > 0 {
        rxShape = newShaper(cfg.Delay, cfg.Jitter, cfg.ShapeBufMB<<20, func(pkt []byte, n int) {
            writeTun(pkt[:n])
            putPkt(pkt)
        })
    }

    // deliver внедряет СОБРАННЫЙ пакет: напрямую в TUN либо через шейпер.
    // Размер пакета определяется как len(src) — вызывающий не может по ошибке
    // передать длину отдельного куска вместо целого пакета.
    deliver := func(src []byte) {
        if rxShape != nil {
            pkt := getPkt()
            copy(pkt[:len(src)], src)
            rxShape.Submit(pkt, len(src))
        } else {
            writeTun(src)
        }
    }

    defer func() {
        if rxShape != nil {
            rxShape.Close() // упорядоченно сливает остаток очереди
        }
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

        // Нарушение формата = рассинхронизация; проверки вне switch,
        // поэтому голый break корректно покидает внешний цикл.
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
        payload := frame[:payLen] // паддинг за пределами payLen игнорируется

        switch mode {
        case stIdle:
            if flags&flagFirst == 0 {
                log.Printf("Кадр без FIRST в состоянии IDLE (len=%d, flags=%#02x) — разрыв", payLen, flags)
                break readLoop
            }

            if flags&flagLast != 0 {
                // Быстрый путь: целый пакет одним кадром, без сборки.
                deliver(payload)
                continue
            }

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
                deliver(acc) // ← фикс: был deliver(acc, payLen) — обрезал пакет до последнего куска
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
