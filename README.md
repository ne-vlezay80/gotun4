L2/L3 туннель поверх TCP

Опции:
```
  -addr string
        Адрес подключения/прослушивания (default "127.0.0.1:1080")
  -chunk int
        Базовый размер кадра для обоих направлений; <=0 — переменная длина (default 1400)
  -chunkrx int
        Входящие кадры (пир -> МЫ): N>0 — ожидается строго N, несовпадение = разрыв; <=0 — без контроля; по умолчанию как -chunk
  -chunktx int
        Исходящие кадры (МЫ -> пир): N>0 — фиксированные с добивкой до N; по умолчанию как -chunk
  -delay duration
        Базовая задержка для обоих направлений
  -delayrx duration
        Задержка TCP->TUN; по умолчанию как -delay
  -delaytx duration
        Задержка TUN->TCP; по умолчанию как -delay
  -jitter duration
        Случайная добавка 0..jitter для обоих направлений (uniform)
  -jitterrx duration
        Джиттер TCP->TUN; по умолчанию как -jitter
  -jittertx duration
        Джиттер TUN->TCP; по умолчанию как -jitter
  -keepalive
        Управление флагом TCP_KEEPALIVE (default true)
  -mode string
        Режим работы: client или server (default "client")
  -mtu int
        MTU интерфейса (<=0 — не менять) (default 1400)
  -nodelay
        Управление флагом TCP_NODELAY (default true)
  -padmode string
        Заполнитель паддинга фиксированных кадров: zero|random (default "zero")
  -persist
        Оставлять интерфейс после выхода (TUNSETPERSIST)
  -procs int
        Ограничить число ядер (GOMAXPROCS); 0 — решение рантайма
  -proxy string
        SOCKS5-прокси для исходящих подключений (client): host:port или socks5://user:pass@host:port
  -rxbuf int
        Входящий буфер TCP в МБ (default 32)
  -shapebuf int
        Лимит очереди шейпера в МБ на направление (default 16)
  -tun string
        Имя TUN интерфейса (default "tun0")
  -tunmode string
        Режим TUN интерфейса (tun/tap) (default "tun")
  -txbuf int
        Исходящий буфер TCP в МБ (default 32)
```
