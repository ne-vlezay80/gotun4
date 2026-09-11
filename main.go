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
// строго сохраняется (FIFO): дедлайн пакета не бывает раньше дедлайна
// предыдущего, а при равных дедлайнах порядок фиксируется порядковым
// номером приёма — перестановок нет даже при клэмпе и грубых часах.
// Шейперы TX и RX независимы (можно включить только одно направление).
// Односторонняя задержка A->B = delaytx(A) + delayrx(B). Очередь каждого
// шейпера ограничена по байтам (-shapebuf, на направление), переполнение =
// tail-drop. Учёт памяти ведётся по реальному размеру буферов очереди.
//
// Судьба очередей шейпера при обрыве TCP: очередь RX (от пира) гибнет
// вместе с соединением; очередь TX (от TUN) переживает обрыв и выдаётся
// в следующее соединение. Для IP-туннеля оба поведения корректны.
//
// Сервер обслуживает одного клиента: слот занят до смерти старого
// соединения (при полной тишине детектится keepalive, ~60 с); новые
// подключения в это время отклоняются.
//
// SOCKS5-прокси (-proxy, только для -mode client): исходящие подключения
// идут через прокси. Формат: host:port либо socks5://[user:pass@]host:port
// (socks5h:// — синоним). user:pass со спецсимволами — в percent-encoding.
// Аутентификация по логину/паролю (RFC 1929) включается автоматически при
// наличии user:pass. Имена целей локально НЕ резолвятся: в CONNECT уходит
// домен, его разрешает прокси (семантика socks5h); IP подставляются байтами.
// Рукопожатие ограничено таймаутом дозвона; после успеха соединение —
// обычный транспорт кадров. В режиме server -proxy игнорируется
// (с предупреждением). Опечатка в -proxy = отказ старта, а не тихий обход.
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
    "fmt"
    "io"
    "log"
    mrand "math/rand/v2"
    "net"
    "net/url"
    "os"
    "runtime"
    "strconv"
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

    // Общий таймаут дозвона; он же ограничивает всю фазу рукопожатия SOCKS5.
    clientDialTimeout = 10 * time.Second
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

    // Proxy != nil — исходящие подключения клиента через SOCKS5.
    // Заполняется только для -mode client (см. -proxy).
    Proxy *url.URL
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
func newPadFiller(mode string) (func([]byte), error) {
    switch mode {
    case "random":
        var seed [32]byte
        if _, err := crand.Read(seed[:]); err != nil {
            return nil, fmt.Errorf("crypto/rand недоступен: %w", err)
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
        }, nil
    default: // "zero"
        return func(b []byte) { clear(b) }, nil
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
    seq uint64 // порядок приёма: при равных `at` гарантирует строгий FIFO
    pkt []byte // буфер из pktPool (НЕ срезанный); владение переходит к out()
    n   int    // размер пакета (payload) внутри pkt, как передан в Submit
    sz  int    // cap(pkt) — реальный удерживаемый объём (для учёта очереди)
}

type schedQueue []schedItem

func (q schedQueue) Len() int { return len(q) }

// Less с тай-брейком по seq: heap.Pop среди равных ключей иначе не даёт
// НИКАКИХ гарантий порядка, а клэмп дедлайнов по lastAt порождает равные
// `at` штатно (при джиттере и на часах с грубым разрешением).
func (q schedQueue) Less(i, j int) bool {
    if q[i].at.Equal(q[j].at) {
        return q[i].seq < q[j].seq
    }
    return q[i].at.Before(q[j].at)
}

func (q schedQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *schedQueue) Push(x any)   { *q = append(*q, x.(schedItem)) }
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
    seq     uint64    // монотонный счётчик принятых пакетов (тай-брейк кучи)
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
// предыдущий и порядок нарушился. При jitter == 0 клэмп — no-op. При равных
// дедлайнах порядок выдачи фиксируется seq — строго в порядке приёма.
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
    s.seq++
    heap.Push(&s.q, schedItem{at: at, seq: s.seq, pkt: pkt, n: n, sz: sz})
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
    os.Exit(run())
}

// run возвращает код выхода. Ошибки завершения возвращаются наверх, а не
// завершают процесс через log.Fatalf: os.Exit обходит defer, и закрытие
// TUN-файла (и любое будущее освобождение ресурсов) не выполнялось бы.
func run() int {
    mode := flag.String("mode", "client", "Режим работы: client или server")
    tunName := flag.String("tun", "tun0", "Имя TUN интерфейса")
    tunMode := flag.String("tunmode", "tun", "Режим TUN интерфейса (tun/tap)")
    addr := flag.String("addr", "127.0.0.1:1080", "Адрес подключения/прослушивания")
    proxy := flag.String("proxy", "", "SOCKS5-прокси для исходящих подключений (client): host:port или socks5://user:pass@host:port")
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

    // SOCKS5-прокси валидируем на старте: молча уйти напрямую из-за опечатки
    // недопустимо — это изменение маршрутизации трафика, а не косметика.
    if *proxy != "" {
        switch *mode {
        case "server":
            log.Printf("Предупреждение: -proxy игнорируется в режиме server (прокси применяется только к исходящим подключениям клиента)")
        case "client":
            u, err := parseProxyURL(*proxy)
            if err != nil {
                log.Printf("Ошибка: некорректный -proxy %q: %v", *proxy, err)
                return 1
            }
            cfg.Proxy = u
            authNote := "без аутентификации"
            if u.User != nil && u.User.Username() != "" {
                authNote = "с аутентификацией (RFC 1929)"
            }
            log.Printf("Исходящие подключения через SOCKS5 %s (%s); имена целей резолвит прокси", u.Host, authNote)
        }
    }

    padFill, err := newPadFiller(cfg.PadMode)
    if err != nil {
        log.Printf("Критично: %v", err)
        return 1
    }

    ifce, ifName, err := openTun(*tunName, tm == "tap", *persist)
    if err != nil {
        log.Printf("Ошибка создания TUN: %v", err)
        return 1
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
        var lastErrLog time.Time
        for {
            // n <= maxPacketSize гарантировано размером среза в Read.
            n, err := ifce.Read(buf[frameHdrSize:])
            if err != nil {
                // Закрытый fd даёт *fs.PathError вокруг os.ErrClosed.
                if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
                    return
                }
                // Интерфейс исчез/упал: это не разрыв туннеля, но и крутить
                // горячий цикл молча нельзя — лог не чаще dropLogPeriod
                // и пауза против busy-loop.
                if time.Since(lastErrLog) >= dropLogPeriod {
                    lastErrLog = time.Now()
                    log.Printf("Ошибка чтения TUN: %v (продолжаю)", err)
                }
                time.Sleep(10 * time.Millisecond)
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
        if err := runServer(ifce, *addr, state, cfg); err != nil {
            log.Printf("Ошибка запуска сервера: %v", err)
            return 1
        }
    case "client":
        runClient(ifce, *addr, state, cfg)
    default:
        log.Printf("Неизвестный режим: %s", *mode)
        return 1
    }
    return 0
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
    // Пакет нулевой длины в этом формате непредставим (приёмник считает
    // payLen == 0 рассинхроном и рвёт соединение) — просто игнорируем.
    if n <= 0 {
        return true
    }
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

// ---------------------------- SOCKS5 ----------------------------

// SOCKS5 (RFC 1928) + аутентификация логин/пароль (RFC 1929).
// Реализовано на stdlib сознательно: зависимость от golang.org/x/net
// ради ~50 строк протокола не нужна.
const (
    socksVer5       = 0x05
    socksCmdConnect = 0x01

    socksAuthNone     = 0x00
    socksAuthUserPass = 0x02
    socksAuthBad      = 0xFF // прокси не выбрал ни один предложенный метод

    socksAtypIPv4   = 0x01
    socksAtypDomain = 0x03
    socksAtypIPv6   = 0x04

    socksRepSuccess = 0x00
)

var socksRepText = [...]string{
    "успех",
    "общий сбой SOCKS-сервера",
    "соединение запрещено правилами",
    "сеть недостижима",
    "хост недостижим",
    "отказ в соединении",
    "истёк TTL",
    "команда не поддерживается",
    "тип адреса не поддерживается",
}

// parseProxyURL разбирает значение -proxy: голый "host:port" трактуется
// как socks5, полная форма — "socks5://[user:pass@]host:port" (процентное
// кодирование в user:pass обрабатывается url.Parse). Схема socks5h —
// синоним socks5: имена целей в обоих случаях резолвит прокси.
func parseProxyURL(s string) (*url.URL, error) {
    if !strings.Contains(s, "://") {
        s = "socks5://" + s
    }
    u, err := url.Parse(s)
    if err != nil {
        return nil, err
    }
    switch u.Scheme {
    case "socks5", "socks5h":
    default:
        return nil, fmt.Errorf("схема %q не поддерживается (ожидается socks5)", u.Scheme)
    }
    if u.Host == "" {
        return nil, errors.New("пустой адрес прокси")
    }
    if p := u.Path; p != "" && p != "/" {
        return nil, fmt.Errorf("лишняя часть пути %q в адресе прокси", p)
    }
    return u, nil
}

// dialSOCKS5 устанавливает TCP-соединение с SOCKS5-прокси и запрашивает
// CONNECT к target ("host:port"). На всю фазу рукопожатия ставится
// дедлайн timeout; после успеха он снимается — соединение становится
// обычным транспортом кадров и живёт неограниченно долго.
func dialSOCKS5(proxy, target string, timeout time.Duration, username, password string, haveAuth bool) (net.Conn, error) {
    d := &net.Dialer{Timeout: timeout}
    conn, err := d.Dial("tcp", proxy)
    if err != nil {
        return nil, fmt.Errorf("подключение к прокси %s: %w", proxy, err)
    }
    conn.SetDeadline(time.Now().Add(timeout))
    if err := socksHandshake(conn, target, username, password, haveAuth); err != nil {
        conn.Close()
        return nil, err
    }
    conn.SetDeadline(time.Time{})
    return conn, nil
}

func socksHandshake(conn net.Conn, target, username, password string, haveAuth bool) error {
    // Цель валидируем до приветствия — нечего нагружать прокси мусором.
    host, portStr, err := net.SplitHostPort(target)
    if err != nil {
        return fmt.Errorf("адрес цели %q: %w", target, err)
    }
    port, err := strconv.Atoi(portStr)
    if err != nil || port <= 0 || port > 65535 {
        return fmt.Errorf("некорректный порт цели %q", portStr)
    }

    // 1) Приветствие: версия + список поддерживаемых методов.
    methods := []byte{socksAuthNone}
    if haveAuth {
        methods = append(methods, socksAuthUserPass)
    }
    greeting := make([]byte, 0, 2+len(methods))
    greeting = append(greeting, socksVer5, byte(len(methods)))
    greeting = append(greeting, methods...)
    if _, err := conn.Write(greeting); err != nil {
        return fmt.Errorf("приветствие прокси: %w", err)
    }

    resp := make([]byte, 2)
    if _, err := io.ReadFull(conn, resp); err != nil {
        return fmt.Errorf("ответ на приветствие: %w", err)
    }
    if resp[0] != socksVer5 {
        return fmt.Errorf("это не SOCKS5 (версия ответа %#02x)", resp[0])
    }
    switch resp[1] {
    case socksAuthNone:
        // ок, без аутентификации
    case socksAuthUserPass:
        if !haveAuth {
            return errors.New("прокси требует логин/пароль, а в -proxy учётные данные не указаны (socks5://user:pass@host:port)")
        }
        if err := socksAuth(conn, username, password); err != nil {
            return err
        }
    case socksAuthBad:
        return errors.New("прокси не принял ни один из предложенных методов аутентификации")
    default:
        return fmt.Errorf("прокси выбрал неизвестный метод %#02x", resp[1])
    }

    // 2) CONNECT к цели. IP подставляется байтами (IPv4/IPv6), имя —
    // доменным ATYP: резолвить будет прокси (семантика socks5h).
    req := make([]byte, 0, 7+len(host))
    req = append(req, socksVer5, socksCmdConnect, 0x00)
    if ip := net.ParseIP(host); ip != nil {
        if v4 := ip.To4(); v4 != nil {
            req = append(req, socksAtypIPv4)
            req = append(req, v4...)
        } else {
            req = append(req, socksAtypIPv6)
            req = append(req, ip.To16()...)
        }
    } else {
        if host == "" || len(host) > 255 {
            return fmt.Errorf("имя цели %q непригодно (пустое или длиннее 255 байт)", host)
        }
        req = append(req, socksAtypDomain, byte(len(host)))
        req = append(req, host...)
    }
    req = append(req, byte(port>>8), byte(port))
    if _, err := conn.Write(req); err != nil {
        return fmt.Errorf("запрос CONNECT: %w", err)
    }

    // 3) Ответ: [ver rep rsv atyp][адрес][порт BE16]. Адрес читаем и
    // выбрасываем — транспорт уже установлен, BND.ADDR нам не нужен.
    head := make([]byte, 4)
    if _, err := io.ReadFull(conn, head); err != nil {
        return fmt.Errorf("ответ на CONNECT: %w", err)
    }
    if head[0] != socksVer5 {
        return fmt.Errorf("CONNECT: неожиданная версия ответа %#02x", head[0])
    }
    if head[1] != socksRepSuccess {
        msg := ""
        if int(head[1]) < len(socksRepText) {
            msg = ": " + socksRepText[head[1]]
        }
        return fmt.Errorf("прокси отклонил CONNECT (код %d%s)", head[1], msg)
    }
    var addrLen int
    switch head[3] {
    case socksAtypIPv4:
        addrLen = 4
    case socksAtypDomain:
        var l [1]byte
        if _, err := io.ReadFull(conn, l[:]); err != nil {
            return fmt.Errorf("CONNECT (длина имени): %w", err)
        }
        addrLen = int(l[0])
    case socksAtypIPv6:
        addrLen = 16
    default:
        return fmt.Errorf("CONNECT: неизвестный тип адреса %#02x", head[3])
    }
    tail := make([]byte, addrLen+2) // адрес + порт
    if _, err := io.ReadFull(conn, tail); err != nil {
        return fmt.Errorf("CONNECT (адрес/порт): %w", err)
    }
    return nil
}

// socksAuth — subnegotiation логин/пароль (RFC 1929).
func socksAuth(conn net.Conn, username, password string) error {
    if len(username) > 255 || len(password) > 255 {
        return errors.New("логин/пароль прокси длиннее 255 байт")
    }
    req := make([]byte, 0, 3+len(username)+len(password))
    req = append(req, 0x01, byte(len(username)))
    req = append(req, username...)
    req = append(req, byte(len(password)))
    req = append(req, password...)
    if _, err := conn.Write(req); err != nil {
        return fmt.Errorf("аутентификация на прокси: %w", err)
    }
    resp := make([]byte, 2)
    if _, err := io.ReadFull(conn, resp); err != nil {
        return fmt.Errorf("ответ аутентификации: %w", err)
    }
    if resp[0] != 0x01 {
        return fmt.Errorf("неожиданная версия subnegotiation %#02x", resp[0])
    }
    if resp[1] != 0x00 {
        return errors.New("прокси отклонил логин/пароль")
    }
    return nil
}

// ---------------------------- server/client ----------------------------

func runServer(ifce *os.File, addr string, state *SafeConn, cfg *Config) error {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return err
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
    dialer := &net.Dialer{Timeout: clientDialTimeout}
    for {
        log.Printf("Клиент подключается к %s...", addr)

        var tcpConn net.Conn
        var err error
        if cfg.Proxy != nil {
            // Учётные данные из URL; percent-encoding уже раскодирован
            // url.Parse. Пустое имя пользователя считаем отсутствием auth.
            user, pass := "", ""
            haveAuth := cfg.Proxy.User != nil && cfg.Proxy.User.Username() != ""
            if haveAuth {
                user = cfg.Proxy.User.Username()
                pass, _ = cfg.Proxy.User.Password()
            }
            tcpConn, err = dialSOCKS5(cfg.Proxy.Host, addr, clientDialTimeout, user, pass, haveAuth)
        } else {
            tcpConn, err = dialer.Dial("tcp", addr)
        }
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
            // Все нарушения — единый выход через break readLoop.
            if flags&flagFirst != 0 {
                log.Println("Новый FIRST посреди незавершённого пакета — разрыв")
                break readLoop
            }
            base := len(acc)
            if base+payLen > maxPacketSize {
                log.Printf("Собранный пакет превысил лимит %d байт — разрыв", maxPacketSize)
                break readLoop
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
    // Ошибки установки опций не фатальны, но молчать о них нельзя:
    // неприменившийся SetReadBuffer (малый rmem_max) выглядит потом
    // как необъяснимые потери на высоких скоростях.
    if err := tcp.SetNoDelay(cfg.NoDelay); err != nil {
        log.Printf("TCP_NODELAY=%v: %v", cfg.NoDelay, err)
    }
    if cfg.KeepAlive {
        // SetKeepAlivePeriod объявлен deprecated с Go 1.23.
        // Count: 3 — смерть пира детектируется за ~Idle + 3*Interval (~60 с)
        // вместо ~150 с с системным Count=9 (Linux). Для туннеля важно
        // освобождать серверный слот без долгого зависания.
        if err := tcp.SetKeepAliveConfig(net.KeepAliveConfig{
            Enable:   true,
            Idle:     15 * time.Second,
            Interval: 15 * time.Second,
            Count:    3,
        }); err != nil {
            log.Printf("keepalive: %v", err)
        }
    } else if err := tcp.SetKeepAlive(false); err != nil {
        log.Printf("keepalive off: %v", err)
    }
    if mb := cfg.RxBufferMB * 1024 * 1024; mb > 0 {
        if err := tcp.SetReadBuffer(mb); err != nil {
            log.Printf("буфер RX %d МБ не применён: %v", cfg.RxBufferMB, err)
        }
    }
    if mb := cfg.TxBufferMB * 1024 * 1024; mb > 0 {
        if err := tcp.SetWriteBuffer(mb); err != nil {
            log.Printf("буфер TX %d МБ не применён: %v", cfg.TxBufferMB, err)
        }
    }
}
