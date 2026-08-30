//go:build linux

// L3/L2 туннель поверх TCP. Формат кадра v3:
//
//	[флаги u8][wireLen BE16][payLen BE16][wireLen байт данных]
//
//	wireLen — сколько байт идёт за заголовком (полезные данные + паддинг),
//	payLen  — сколько из них реальные данные (payLen <= wireLen).
//	флаги: 0x01 = FIRST, 0x02 = LAST; FIRST|LAST — целый пакет одним кадром.
//
// Кадрирование (-chunk, -chunktx, -chunkrx). Размер кадра на проводе
// определяет ОТПРАВИТЕЛЬ:
//
//	-chunktx N: наши кадры несут ровно N байт провода — данные добиваются
//	            до N или режутся на куски; N <= 0 — переменная длина.
//	-chunkrx N: от пира ожидается кадр ровно N байт; иная длина — разрыв
//	            (защита от рассинхрона конфигураций); N <= 0 — приём без
//	            контроля размера.
//	-chunk задаёт сразу оба направления; явно заданные -chunktx/-chunkrx
//	переопределяют своё направление (в т.ч. нулём — «выключить»).
//	Асимметричный канал задаётся зеркальными конфигурациями:
//	    A: -chunktx 600  -chunkrx 1400
//	    B: -chunktx 1400 -chunkrx 600    (A->B кадры 600, B->A кадры 1400)
//
// Паддинг (-padmode): чем заполняется slack-область фиксированных кадров —
// нулями или криптостойкой псевдослучайностью (ChaCha8). Это маскировка
// slack-области, а НЕ шифрование: длины кадров и тайминги остаются открытыми.
//
// Шейпер (-delaytx/-jittertx, -delayrx/-jitterrx; -delay/-jitter — оба
// направления сразу): задерживает выдачу каждого пакета на delay +
// равномерный джиттер [0, jitter); пакет выдаётся целиком. Порядок пакетов
// сохраняется (FIFO): дедлайн пакета не может оказаться раньше дедлайна
// предыдущего — иначе при джиттере возможны перестановки. Шейперы TX и RX
// независимы (можно включить только одно направление). Односторонняя
// задержка A->B = delaytx(A) + delayrx(B). Очередь каждого шейпера
// ограничена по байтам (-shapebuf, на направление), переполнение =
// tail-drop. Учёт памяти ведётся по реальному размеру буферов очереди.
//
// Многопроцессорность: рантайм Go сам использует все ядра; флаг -procs
// позволяет лишь явно ограничить параллелизм (GOMAXPROCS).
//
// Ошибки TUN (интерфейс down) НЕ разрывают TCP: пакеты молча дропаются,
// поток возобновляется автоматически. Разрыв — только ошибка TCP или
// нарушение протокола (в т.ч. кадр не того размера при -chunkrx > 0).
//
// Требуется Go >= 1.23 (math/rand/v2, clear, SetKeepAliveConfig).
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
    "strings"
    "sync"
    "syscall"
    "time"
    "unsafe"
)

const (
    TUNSETIFF     = 0x400454ca
    TUNSETPERSIST = 0x400454cb
    SIOCSIFMTU    = 0x8922
    IFF_TUN       = 0x0001
    IFF_TAP       = 0x0002
    IFF_NO_PI     = 0x1000

    flagFirst     = 0x01
    flagLast      = 0x02
    validFlags    = flagFirst | flagLast
    frameHdrSize  = 5
    maxPacketSize = 65535
    dropLogPeriod = 10 * time.Second
    maxShapeBufMB = 4096 // защита от переполнения при абсурдных значениях -shapebuf
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

    ChunkTX int // размер кадров, которые МЫ отправляем; <=0 — переменная длина
    ChunkRX int // ожидаемый размер кадров ОТ ПИРА; >0 — строгая проверка

    DelayTX  time.Duration
    JitterTX time.Duration
    DelayRX  time.Duration
    JitterRX time.Duration

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

func getPkt() []byte  { return pktPool.Get().([]byte) }
func putPkt(b []byte) { pktPool.Put(b) }

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

// shapeBufBytes переводит лимит очереди из МБ в байты. Считаем в int64
// и клэмпим к максимуму int: на 32-битных платформах int 32-битный, и
// 4096<<20 = 2^32 в нём не помещается — молча обратилось бы в 0 и
// отключило бы учёт очереди (шейпер дропал бы всё).
func shapeBufBytes(mb int) int {
    const maxInt = int64(^uint(0) >> 1)
    v := int64(mb) << 20
    if v > maxInt {
        return int(maxInt)
    }
    return int(v)
}

type schedItem struct {
    at  time.Time
    pkt []byte // буфер из pktPool (НЕ срезанный); владение переходит к out()
    n   int    // размер пакета (payload) внутри pkt, как передан в Submit
    sz  int    // cap(pkt) — реальный удерживаемый объём (для учёта очереди)
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
    closed  bool
    q       schedQueue
    bytes   int
    lastAt  time.Time // дедлайн последнего ПРИНЯТОГО пакета (FIFO при джиттере)
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

// Submit принимает владение pkt. Буфер должен быть из pktPool и НЕ срезан:
// учёт очереди ведётся по cap(pkt), а пул переиспользует буферы целиком.
// Никогда не блокирует: при переполнении — tail-drop пакета.
// Учёт ведётся по cap(pkt): элемент очереди удерживает ВЕСЬ буфер из пула
// (frameHdrSize+maxPacketSize), а не только полезную нагрузку — иначе
// очередь из мелких пакетов незаметно съедает на порядки больше лимита.
//
// Дедлайн делается монотонным (не раньше дедлайна предыдущего принятого
// пакета): иначе при джиттере пакет с малой случайной добавкой обогнал бы
// предыдущий и порядок нарушился. При jitter == 0 клэмп — no-op.
func (s *shaper) Submit(pkt []byte, n int) {
    at := time.Now().Add(s.delay)
    if s.jitter > 0 {
        at = at.Add(time.Duration(mrand.Int64N(int64(s.jitter))))
    }

    sz := cap(pkt)

    s.mu.Lock()
    if s.closed {
        s.mu.Unlock()
        putPkt(pkt)
        return
    }
    if s.bytes+sz > s.maxBytes {
        if time.Since(s.lastLog) >= dropLogPeriod {
            s.lastLog = time.Now()
            log.Printf("Шейпер: очередь переполнена (%d/%d байт удержания), пакет %d байт (буфер %d) отброшен (tail-drop)",
                s.bytes, s.maxBytes, n, sz)
        }
        s.mu.Unlock()
        putPkt(pkt)
        return
    }
    if at.Before(s.lastAt) {
        at = s.lastAt
    }
    s.lastAt = at
    s.bytes += sz
    heap.Push(&s.q, schedItem{at: at, pkt: pkt, n: n, sz: sz})
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
            select {
            case <-s.done:
                return // после Close созревшие пакеты больше не выдаём
            default:
            }
            s.mu.Lock()
            if len(s.q) == 0 || s.q[0].at.After(now) {
                s.mu.Unlock()
                break
            }
            it := heap.Pop(&s.q).(schedItem)
            s.bytes -= it.sz
            s.mu.Unlock()

            s.out(it.pkt, it.n)
        }
    }
}

// drain возвращает оставшиеся в очереди буферы в пул (пакеты отбрасываются).
func (s *shaper) drain() {
    s.mu.Lock()
    for _, it := range s.q {
        putPkt(it.pkt)
    }
    s.q = s.q[:0]
    s.bytes = 0
    s.mu.Unlock()
}

// Close идемпотентен. После Close Submit лишь освобождает буферы,
// выдача созревших пакетов прекращается, остаток очереди сливается в пул.
func (s *shaper) Close() {
    s.mu.Lock()
    if s.closed {
        s.mu.Unlock()
        return
    }
    s.closed = true
    s.mu.Unlock()
    close(s.done)
}

// ---------------------------- main ----------------------------

func main() {
    mode := flag.String("mode", "client", "Режим работы: client или server")
    tunName := flag.String("tun", "tun0", "Имя TUN интерфейса")
    tunMode := flag.String("tunmode", "tun", "Режим TUN интерфейса (tun/tap)")
    addr := flag.String("addr", "127.0.0.1:1080", "Адрес подключения/прослушивания")
    mtu := flag.Int("mtu", 1400, "MTU интерфейса (<=0 — не менять)")
    persist := flag.Bool("persist", false, "Оставлять интерфейс после выхода (TUNSETPERSIST)")

    // Кадрирование: -chunk задаёт базу для обоих направлений,
    // -chunktx/-chunkrx, заданные явно, переопределяют своё.
    chunk := flag.Int("chunk", 1400, "Базовый размер кадра для обоих направлений; <=0 — переменная длина")
    chunkTX := flag.Int("chunktx", 0, "Исходящие кадры (МЫ -> пир): N>0 — фиксированные с добивкой до N; по умолчанию как -chunk")
    chunkRX := flag.Int("chunkrx", 0, "Входящие кадры (пир -> МЫ): N>0 — ожидается строго N, несовпадение = разрыв; <=0 — без контроля; по умолчанию как -chunk")

    // Шейпер: -delay/-jitter задают базу для обоих направлений,
    // -delaytx/-delayrx/..., заданные явно, переопределяют своё.
    delay := flag.Duration("delay", 0, "Базовая задержка для обоих направлений")
    jitter := flag.Duration("jitter", 0, "Случайная добавка 0..jitter для обоих направлений (uniform)")
    delayTX := flag.Duration("delaytx", 0, "Задержка TUN->TCP; по умолчанию как -delay")
    jitterTX := flag.Duration("jittertx", 0, "Джиттер TUN->TCP; по умолчанию как -jitter")
    delayRX := flag.Duration("delayrx", 0, "Задержка TCP->TUN; по умолчанию как -delay")
    jitterRX := flag.Duration("jitterrx", 0, "Джиттер TCP->TUN; по умолчанию как -jitter")

    shapebuf := flag.Int("shapebuf", 16, "Лимит очереди шейпера в МБ на направление")
    padmode := flag.String("padmode", "zero", "Заполнитель паддинга фиксированных кадров: zero|random")
    procs := flag.Int("procs", 0, "Ограничить число ядер (GOMAXPROCS); 0 — решение рантайма")

    tcpnodelay := flag.Bool("nodelay", true, "Управление флагом TCP_NODELAY")
    tcpkeepalive := flag.Bool("keepalive", true, "Управление флагом TCP_KEEPALIVE")
    tcprxbuf := flag.Int("rxbuf", 32, "Входящий буфер TCP в МБ")
    tcptxbuf := flag.Int("txbuf", 32, "Исходящий буфер TCP в МБ")

    flag.Parse()

    // Per-direction флаги действуют, только если заданы в командной строке:
    // тогда они переопределяют базу (-chunk/-delay/-jitter), включая явный
    // ноль («выключить фичу на этом направлении»).
    set := map[string]bool{}
    flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

    cfg := &Config{
        NoDelay:    *tcpnodelay,
        KeepAlive:  *tcpkeepalive,
        RxBufferMB: *tcprxbuf,
        TxBufferMB: *tcptxbuf,
        ChunkTX:    *chunk,
        ChunkRX:    *chunk,
        DelayTX:    *delay,
        JitterTX:   *jitter,
        DelayRX:    *delay,
        JitterRX:   *jitter,
        ShapeBufMB: *shapebuf,
        PadMode:    *padmode,
    }
    if set["chunktx"] {
        cfg.ChunkTX = *chunkTX
    }
    if set["chunkrx"] {
        cfg.ChunkRX = *chunkRX
    }
    if set["delaytx"] {
        cfg.DelayTX = *delayTX
    }
    if set["jittertx"] {
        cfg.JitterTX = *jitterTX
    }
    if set["delayrx"] {
        cfg.DelayRX = *delayRX
    }
    if set["jitterrx"] {
        cfg.JitterRX = *jitterRX
    }

    if cfg.ChunkTX > maxPacketSize {
        log.Printf("-chunktx %d больше максимума (%d), ограничен", cfg.ChunkTX, maxPacketSize)
        cfg.ChunkTX = maxPacketSize
    }
    if cfg.ChunkRX > maxPacketSize {
        log.Printf("-chunkrx %d больше максимума (%d), ограничен", cfg.ChunkRX, maxPacketSize)
        cfg.ChunkRX = maxPacketSize
    }
    if cfg.PadMode != "zero" && cfg.PadMode != "random" {
        log.Printf("-padmode %q неизвестен, использую zero", cfg.PadMode)
        cfg.PadMode = "zero"
    }
    if cfg.ShapeBufMB <= 0 {
        log.Printf("-shapebuf %d некорректен, использую 16 МБ", cfg.ShapeBufMB)
        cfg.ShapeBufMB = 16
    } else if cfg.ShapeBufMB > maxShapeBufMB {
        log.Printf("-shapebuf %d слишком велик, ограничен %d МБ", cfg.ShapeBufMB, maxShapeBufMB)
        cfg.ShapeBufMB = maxShapeBufMB
    }

    tm := strings.ToLower(*tunMode)
    if tm != "tun" && tm != "tap" {
        log.Printf("-tunmode %q неизвестен, использую tun", *tunMode)
        tm = "tun"
    }

    if *procs > 0 {
        prev := runtime.GOMAXPROCS(*procs)
        log.Printf("GOMAXPROCS: %d -> %d", prev, *procs)
    }

    ifce, ifName, err := openTun(*tunName, tm == "tap", *persist)
    if err != nil {
        log.Fatalf("Ошибка создания TUN: %v", err)
    }
    defer ifce.Close()

    if *mtu > 0 {
        if err := setInterfaceMTU(ifName, *mtu); err != nil {
            log.Printf("Предупреждение: не удалось выставить MTU=%d у %s: %v", *mtu, ifName, err)
        } else {
            log.Printf("MTU интерфейса %s установлен в %d", ifName, *mtu)
        }
    }

    if cfg.ChunkTX > 0 {
        log.Printf("Исходящие кадры: фиксированные %d байт (+%d заголовок), паддинг: %s", cfg.ChunkTX, frameHdrSize, cfg.PadMode)
    } else {
        log.Println("Исходящие кадры: переменной длины, без дробления")
    }
    if cfg.ChunkRX > 0 {
        log.Printf("Входящие кадры: ожидается ровно %d байт (несовпадение = разрыв)", cfg.ChunkRX)
    } else {
        log.Println("Входящие кадры: контроль размера выключен")
    }
    if cfg.DelayTX > 0 || cfg.JitterTX > 0 || cfg.DelayRX > 0 || cfg.JitterRX > 0 {
        log.Printf("Шейпер: TX(delay=%s jitter=%s) RX(delay=%s jitter=%s); задержка A->B = delaytx(A)+delayrx(B); очередь %d МБ на направление",
            cfg.DelayTX, cfg.JitterTX, cfg.DelayRX, cfg.JitterRX, cfg.ShapeBufMB)
    }

    state := &SafeConn{}
    padFill := newPadFiller(cfg.PadMode)

    // Единая точка отправки в TCP (вызывается ТОЛЬКО из одной горутины:
    // либо цикл чтения TUN, либо диспетчер шейпера — одновременно никогда).
    sendOverTCP := func(conn net.Conn, pkt []byte, n int) {
        ok := emitFrames(conn, pkt, n, cfg.ChunkTX, padFill)
        putPkt(pkt)
        if !ok {
            state.ClearIfCurrent(conn)
            conn.Close()
        }
    }

    // Исходящий шейпер (TUN -> TCP): параметры TX-направления.
    // nil = выключен, прямой путь без копий.
    var txShape *shaper
    if cfg.DelayTX > 0 || cfg.JitterTX > 0 {
        txShape = newShaper(cfg.DelayTX, cfg.JitterTX, shapeBufBytes(cfg.ShapeBufMB), func(pkt []byte, n int) {
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
            // n <= maxPacketSize гарантировано размером среза в Read.
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

            conn := state.Get()
            if conn == nil {
                continue // нет активного соединения — пакет отбрасываем
            }

            if txShape == nil {
                // Быстрый путь: пакет уже лежит за заголовком, без копий.
                if !emitFrames(conn, buf, n, cfg.ChunkTX, padFill) {
                    state.ClearIfCurrent(conn)
                    conn.Close()
                }
                continue
            }

            // Копия в пул: buf переиспользуется, а пакет полежит в очереди.
            // Буфер передаётся НЕ срезанным — размер (n) шейпер хранит явно.
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

func openTun(name string, isTAP bool, wantPersist bool) (*os.File, string, error) {
    fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
    if err != nil {
        return nil, "", err
    }

    // ВАЖНО: IFF_PERSIST нельзя передавать в TUNSETIFF — ядро отвергает
    // неизвестные биты с EINVAL (см. tun_set_iff в drivers/net/tun.c).
    // Персистентность включается отдельным ioctl TUNSETPERSIST ниже.
    var flags uint16 = IFF_NO_PI
    if isTAP {
        flags |= IFF_TAP
    } else {
        flags |= IFF_TUN
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
        return nil, "", errno
    }

    if wantPersist {
        // TUNSETPERSIST принимает значение напрямую, не указатель.
        if _, _, errno := syscall.Syscall(
            syscall.SYS_IOCTL,
            uintptr(fd),
            uintptr(TUNSETPERSIST),
            1,
        ); errno != 0 {
            syscall.Close(fd)
            return nil, "", errno
        }
    }

    // Ядро записывает фактическое имя обратно в ifr.Name — важно для
    // "tun%d", шаблонных или пустых имён: дальше используем именно его.
    actual := strings.TrimRight(string(ifr.Name[:]), "\x00")

    kind := "TUN"
    if isTAP {
        kind = "TAP"
    }
    extra := ""
    if wantPersist {
        extra = " (persist)"
    }
    log.Printf("Открыт %s-интерфейс %q%s", kind, actual, extra)

    return os.NewFile(uintptr(fd), kind+":"+actual), actual, nil
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
    // Таймаут дозвона обязателен: без него на фильтрующих сетях (тихий
    // drop SYN) Dial висит минутами и backoff не работает.
    dialer := &net.Dialer{Timeout: 10 * time.Second}
    for {
        log.Printf("Клиент подключается к %s...", addr)
        tcpConn, err := dialer.Dial("tcp", addr)
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

    // Входной шейпер (TCP -> TUN): параметры RX-направления.
    // После полной сборки пакет ждёт своего срока и внедряется в TUN.
    // nil = прямой путь.
    var rxShape *shaper
    if cfg.DelayRX > 0 || cfg.JitterRX > 0 {
        rxShape = newShaper(cfg.DelayRX, cfg.JitterRX, shapeBufBytes(cfg.ShapeBufMB), func(pkt []byte, n int) {
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
            rxShape.Close() // остаток очереди отбрасывается, буферы — в пул
        }
        state.ClearIfCurrent(tcpConn)
        tcpConn.Close()
        log.Println("Обработчик соединения завершён")
    }()

    log.Printf("Туннель запущен. Кадры: [флаги u8][wireLen BE16][payLen BE16][данные+паддинг].")

readLoop:
    for {
        if _, err := io.ReadFull(r, hdr[:]); err != nil {
            // EOF и частичный заголовок — штатное закрытие пира.
            if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
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

        // Профиль входящих кадров: в фиксированном режиме пир обязан слать
        // кадры ровно ChunkRX байт; иное — чужая/несовместимая конфигурация.
        // Проверка ДО чтения тела — рассинхрон ловится дёшево.
        if cfg.ChunkRX > 0 && wireLen != cfg.ChunkRX {
            log.Printf("Кадр %d байт не совпадает с ожидаемым размером %d (-chunkrx) — разрыв", wireLen, cfg.ChunkRX)
            break
        }

        if _, err := io.ReadFull(r, frame[:wireLen]); err != nil {
            // Обрыв посреди тела — тоже штатное закрытие соединения.
            if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
                break
            }
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
                deliver(acc) // размер — весь собранный пакет, не последний кусок
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
    if cfg.KeepAlive {
        // SetKeepAlivePeriod объявлен deprecated с Go 1.23.
        // Count: 3 — смерть пира детектируется за ~Idle + 3*Interval (~60 с)
        // вместо ~150 с с системным Count=9 (Linux). Для туннеля важно
        // освобождать серверный слот без долгого зависания.
        tcp.SetKeepAliveConfig(net.KeepAliveConfig{
            Enable:   true,
            Idle:     15 * time.Second,
            Interval: 15 * time.Second,
            Count:    3,
        })
    } else {
        tcp.SetKeepAlive(false)
    }
    if mb := cfg.RxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetReadBuffer(mb)
    }
    if mb := cfg.TxBufferMB * 1024 * 1024; mb > 0 {
        tcp.SetWriteBuffer(mb)
    }
}
