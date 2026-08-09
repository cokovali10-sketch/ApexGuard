# ApexGuard (AegisX Core Suite) — Technical Design Document

**Версия:** 1.0.0  
**Класс:** Autonomous Enterprise Defense Cluster (EDR/NDR + Deception + Fuzzing + RE)  
**Статус:** Draft / Implementation Blueprint

---

## 1. Общая архитектура и событийная шина (Event Bus)

### 1.1 Топология кластера

Кластер построен по схеме **hub-and-spoke** с центральным шиной `AegisBus` и независимыми дата-плейнами модулей. Каждый модуль — отдельный процесс (микросервис), взаимодействующий строго через:

1. **gRPC (Protobuf v3)** — синхронные вызовы, RPC-команды (блокировка IP, перезагрузка зондов).
2. **Shared Memory + Ring Buffer (Zero-Copy)** — высокочастотные события ядра (syscall trace) с минимальной задержкой.
3. **WebSocket (async push)** — алерты в реальном времени до ApexConsole.
4. **NATS JetStream (optional)** — отказоустойчивая очередь долгоживущих задач (фаззинг, RE-анализ).

```
                     ┌──────────────────────────────────────────────┐
                     │                  APEXCONSOLE                 │
                     │         (3D Dashboard / WebSocket WSS)       │
                     └──────────────▲───────────────────────────────┘
                                    │ gRPC-Web + WS + REST
 ┌────────────┐   ┌────────────────┴─────────────────┐   ┌──────────────┐
 │ KernelShield│──►│                                 │◄──│   HexEye     │
 │ eBPF Agent │   │          AEGIS BUS (Core)        │───│  RE / Static │
 └────────────┘   │  gRPC mux │ Ring Buffer │ Router │   └──────────────┘
 ┌────────────┐   │                                 │   ┌──────────────┐
 │ PulseFuzz  │──►│   Zero-Copy IPC (mmap+AF_XDP)   │◄──│  ShadowNet   │
 │ Go Engine  │   │                                 │   │  Honeynet AI │
 └────────────┘   └───────────────┬─────────────────┘   └──────────────┘
                                  │
                             ┌────▼────┐
                             │  Cache  │  Redis / ClickHouse (event log)
                             └─────────┘
```

### 1.2 IPC и Zero-Copy

**Проблема:** события syscall могут генерироваться >100k events/sec. Копирование через `write()` + `recvmsg()` создаёт лишние 2-3 копии в памяти и латентность ~50-100µs.

**Решение — трехуровневый транспорт:**

1. **eBPF Ring Buffer (`bpf_ringbuf`)** — уже в ядре, строго zero-copy в kernel space. User-space агент подписан через `libbpf` `ring_buffer__new()` с выделенным ядром на NUMA-ноду.
2. **`mmap` Shared Memory + SPSC lock-free queue** — для событий между Rust-агентом и Core. Используется кольцевой буфер с атомарными счётчиками (`AtomicU64` head/tail, memory order `Acquire`/`Release`), исключающий блокировки в hot path.
3. **AF_XDP (eXpress Data Path)** — опционально для перехвата сетевого трафика без копирования в user space (Socket Filter — подключаем к KernelShield для drop-packet при сетевых аномалиях).

```
Kernel space                          User space
[event]──bpf_ringbuf_reserve()───────►[Rust Agent]──AtomicU64 SPSC queue──►[Core]──►[Router]──►[WS/DB]
  (zero copy)                          (zero copy, lock-free)              (gRPC/WebSocket)
```

**Требования к кольцевому буферу (Ring Buffer):**
- Фиксированная аллокация `mmap(MAP_SHARED | MAP_POPULATE)` размером 64MB на модуль.
- Структура слота: `[uint64 seqno | uint32 size | uint32 type | payload[0]]`.
- Продюсер пишет в `buffer[tail & mask]`, атомарно `tail.fetch_add(1, Release)`; консьюмер читает до `head.load(Acquire)`.
- Переполнение: слоты помечаются `DROPPED`, серийный номер позволяет Core детектировать потери и запросить повтор.

### 1.3 Схема Protobuf-событий

Полные определения — в `proto/events.proto`. Ключевые сообщения:

```proto
// ThreatEvent — единое нормализованное событие безопасности.
message ThreatEvent {
  string event_id        = 1;  // UUIDv7, сортируется по времени
  uint64 timestamp_ns    = 2;  // UnixNano
  EventSource source     = 3;  // KERNELSHIELD | PULSEFUZZ | SHADOWNET | HEXEYE
  EventType  type        = 4;  // EXECVE | CONNECT | MUTATION | DECEPTION | ...
  Severity   severity    = 5;  // CRITICAL | HIGH | MEDIUM | LOW | INFO
  string host_id         = 6;  // node ID в 3D-топологии
  string pid_namespace   = 7;
  map<string,string> context = 8; // свободный контекст (argv, cwd, remote_ip...)
  bytes raw_payload      = 9;  // сырые данные (фрагмент пейлоада)
  string mitre_technique = 10; // T1055, T1078 ...
}
```

```proto
// AnomalyAlert — обогащённый алерт после корреляции.
message AnomalyAlert {
  string alert_id        = 1;
  repeated ThreatEvent   evidence = 2; // цепочка событий (attack chain)
  float  risk_score      = 3;         // 0.0..1.0, ML-скор
  string killchain_stage = 4;         // Recon → Weaponization → ...
  string recommendation  = 5;         // текст для оператора
}
```

```proto
// SystemMetric — метрики кластера для 3D-консоли.
message SystemMetric {
  string host_id         = 1;
  float  cpu_usage       = 2;
  uint64 mem_bytes       = 3;
  uint64 net_rx_bytes    = 4;
  uint64 net_tx_bytes    = 5;
  uint32 event_rate_eps  = 6;
  float  latency_ms      = 7;   // end-to-end от ядра до UI
}
```

**gRPC-сервисы:**

```proto
service AegisCore {
  rpc BlockIp(BlockIpRequest) returns (BlockIpResponse);          // команда в KernelShield (iptables/nft + eBPF drop)
  rpc ReloadProbes(ReloadRequest) returns (ReloadResponse);       // перезапуск eBPF-зондов
  rpc TriggerFuzz(FuzzRequest) returns (FuzzJob);                 // запуск PulseFuzz
  rpc SpawnHoneypot(HoneypotSpec) returns (HoneypotStatus);       // ShadowNet
  rpc AnalyzeBinary(BinaryPath) returns (AnalysisReport);         // HexEye
  rpc StreamEvents(StreamFilter) returns (stream ThreatEvent);    // hot path для Console
}
```

---

## 2. Модуль 1: KernelShield (eBPF & System Tracing)

### 2.1 Назначение и позиционирование

Низкоуровневый EDR-агент уровня ядра. Работает на Linux 5.4+ с **CO-RE (Compile Once — Run Everywhere)** через `libbpf`, что позволяет один BPF-объект запускать на разных ядрах без пересборки (BTF-специфичные константы, vmlinux.h, `BPF CO-RE` relocation).

### 2.2 Целевые tracepoint-хуки

| Tracepoint | Цель | Данные |
|---|---|---|
| `sys_enter_execve` / `sys_enter_execveat` | Запуск процессов, файл-less binary, script execution | argv, env, `comm`, `ppid`, creds |
| `sys_enter_connect` | C2-каналы, beaconing, data exfiltration | `sockaddr_in`/`sockaddr_in6` (ip, port) |
| `sys_enter_ptrace` | Debug-инъекции, `PTRACE_TRACEME`, анти-EDR | `request`, pid |
| `sys_enter_openat` + `kprobe/security_file_open` | Подмена бинарников, чтение `/proc/1/environ`, `LD_PRELOAD` | flags, path |
| `sys_enter_setuid`/`setresuid` | LPE-попытки | uid/gid |
| `tracepoint/raw_syscalls` + LSM `bprm_check_security` | Fallback-детект всех syscalls | nr, args |

### 2.3 Детектируемые тактики MITRE ATT&CK

- **T1055 Process Injection**: паттерн `mmap(PROT_WRITE|PROT_EXEC)` + последующий вызов `ptrace(PTRACE_POKEDATA)` → high-risk контекст.
- **T1548.001 Setuid and Setgid**: смена эффективного uid на 0 не-дочерним процессом без `CAP_SETUID`.
- **T1610 Deploy Container**: обход namespace — запись в `/proc/<pid>/ns/*` из контейнера.
- **T1204.002 User Execution / T1059.004**: shell через pipe в `execve` (file-less execution: `fd == -1`).
- **T1071 C2**: `connect()` к non-standard порту + подозрительный TLS handshake (`connect` в `AF_INET` с портом 4444+).

### 2.4 Механизм мгновенной блокировки (Enforcement in Kernel)

Блокировка выполняется **до** возврата в user space, двумя паттернами:

1. **`BPF_LSM` (Linux Security Modules) hook `bpf` LSM attach** — возврат `-EPERM` из LSM-hook убивает системный вызов на уровне ядра, процесс не может его перехватить/повторить. Для `kill`-логики используем `bpf_send_signal()`.
2. **`tracepoint/sys_enter_*` + `bpf_send_signal(SIGKILL)`** — отправка сигнала целевому процессу прямо из BPF-программы (до доставки данных в user space). Латентность блокировки < 1ms.
3. **TC / XDP `BPF_DROP`** — сетевой drop пакета до входа в сетевой стек.

```c
/* Фрагмент: аварийное завершение через сигнал из BPF */
if (is_malicious) {
    bpf_send_signal(SIGKILL);
    bpf_ringbuf_reserve(...);  // лог до убийства
    return 0;                  // (BPF_OK)
}
```

### 2.5 Реализация

- `probes/kernelshield.bpf.c` — BPF-объект (см. код ниже).
- `agent/main.rs` — Rust-агент: загрузка через `libbpf-rs`, `ring_buffer` consumer, обогащение событий (pid→binary path через `/proc`, контейнер ID через cgroup), классификация и передача в AegisBus.
- `cgroup` биндинг: агент присоединяется к `cgroup` по группам, атрибут `container_id` из `bpf_get_current_cgroup_id()`.

**Оверхеды:** ~2-5% CPU на активном ядре при ~100k EPS (свойственно для tracepoint-режима; при большом шуме рекомендуется rate-limit в BPF через `bpf_ktime_get_ns` в течение окна).

---

## 3. Модуль 2: PulseFuzz (Autonomous API & Logic Fuzzer)

### 3.1 Назначение

Высококонкурентный фаззер для веб-API (REST, GraphQL, gRPC) и бизнес-логики. Работает в трёх режимах:

- **Structural**: парсинг OpenAPI v3 / AsyncAPI / GraphQL schema.
- **Semantic (BLA — Business Logic Attacks)**: подмена полей на бизнес-инварианты: отрицательные количества, IDOR-объекты, делегирование прав, повышение тарифных планов без оплаты.
- **Chaos**: WebSocket-брейкпоинты для манипуляции запросами «на лету» (задержки, подмена статус-кодов, обрывы).

### 3.2 Архитектура

```
                  ┌───────────────┐
  OpenAPI v3 ────►│ Schema Parser │──► Operation Tree
                  └───────┬───────┘
                          ▼
                  ┌───────────────┐   channel (worker pool)
  Fuzz Seeds ────►│ Mutator Engine│──►────────────► HTTP/gRPC Senders
                  └───────┬───────┘          (concurrent workers)
                          ▼
                  ┌───────────────┐
                  │  Evaluator    │──► AnomalyDetector (SQLi/SSTI signature,
                  └───────────────┘    timing side-channel, status code policy)
                                          │
                                          ▼
                                   ThreatEvent → AegisBus
```

- **Go worker pool**: `semaphore` (golang.org/x/sync) лимитирует concurrency (по умолчанию 100).
- **Протоколы**: REST через `net/http` + HTTP/2, GraphQL через POST/JSON + introspection, gRPC через `grpc-go` dynamic client (unknown payloads).
- **Логика детекта**: респонс-времени side-channel (`A/B timing`, базовый порог), статус-код policy (200 vs 500), regexp-сигнатуры `SQLITE`, `PG::`, `OperationalError`, `{{.*}}` (SSTI probe), `access denied` отсутствие.

### 3.3 Генерация мутаций

Мутатор применяет **рекурсивную трансформацию JSON-дерева**:

1. **Boundary**: числовые поля — `min-1, max+1, 0, -1, huge (1<<63)`.
2. **Injection vectors**: строковые — `' OR '1'='1`, `" OR 1=1--`, `{{7*7}}`, `${{7*7}}`, `<script>`, NUL, Unicode-нормализация.
3. **Type confusion**: замена `string` на `["x", {"x":1}]`, числа на NaN/Infinity.
4. **IDOR**: подмена `id`, `user_id`, `order_id` на соседние/чужие UUID.
5. **Mass assignment**: добавление полей `role`, `is_admin`, `price`, `balance` в тело запроса.

---

## 4. Модуль 3: ShadowNet (AI Cyber Deception & Honeynet)

### 4.1 Назначение

Автономная ловушка-«десепшн» с генеративным ИИ. Разворачивает изолированные контейнеры-фальшивые сервисы (SSH, HTTP, FTP, RDP) в изолированных сетях (bridge с запретом исходящего к реальной сети). Атакующий взаимодействует с «живой» системой: LLM генерирует правдоподобный контент (вывод bash, файлы `.env`, логи, статус ядра), задерживая атаку и собирая TTPs.

### 4.2 Поток атаки → TTPs

```
Attacker ──► Honeypot SSH ──► SSH Emulator (asyncio)
                │                 │  (bash command)
                ▼                 ▼
          Docker SDK  ◄── Ollama LLM ──► prompt cache
      (spawn fake /root, fake FS, .env)
                │
                ▼
      MITRE Mapper ──► ThreatEvent(TTP) ──► AegisBus ──► Console
```

### 4.3 Компоненты

- **Asyncio TCP-серверы** на портах 22/80/21/3389 (TLS для RDP не обязателен — эмулируем handshake).
- **Shell-эмулятор**: парсинг команд (ls, cat, whoami, id, uname, ifconfig, sudo, nc, wget, curl, base64, python3), маппинг на «фейковый» состояния ФС, генерация вывода через Ollama для произвольных команд.
- **Ollama API** (`/api/generate`, `/api/chat`) — модель `qwen2.5:7b` (локально). Prompt-injection устойчивый: системный промпт запрещает раскрывать, что это ловушка.
- **Docker SDK** (`docker-py`): создание `deception-*` контейнеров с `network_mode: none` для сети, volume с фейковыми файлами, изоляция ресурсов (`--cpus`, `--memory`).
- **MITRE Mapper**: правила сопоставления команд с TTP (например, `find / -perm -4000` → T1548.001, `cat /etc/passwd` → T1082, `wget` → T1105).

---

## 5. Модуль 4: HexEye (Binary & Firmware Reverse Engineering)

### 5.1 Назначение

Статический анализатор исполняемых файлов (ELF/PE) и прошивок. Работает как сервис: принимает путь к файлу, возвращает структурированный отчёт (report + ThreatEvent при находках).

### 5.2 Пайплайн

1. **Disassembler**: Radare2 (`r2pipe` — Python) или Capstone (Rust, `crate capstone`) для x86/x64/ARM.
2. **Parsing ELF/PE**: секции, символическая информация (`.symtab`, PDB), динамические импорты.
3. **Secret Scanner**: сканирование данных и `.rodata`/`.data` на regex: AWS keys (`AKIA[0-9A-Z]{16}`), JWT (`eyJ...`), PEM-ключи, приватные ключи RSA (`-----BEGIN RSA PRIVATE KEY-----`).
4. **Call Graph**: построение графа вызовов из функции → поиск reachability небезопасных sink-функций (`strcpy`, `sprintf`, `gets`, `system`, `memcpy` без проверки длины).
5. **Верификация UAF/Buffer Overflow**: семантика по архитектуре — поиск `sub`/`add` к указателям, отсутствие проверки границ в цикле, `strlen`+`strcpy` паттерны; taint-like tracking по данным пользовательского ввода (`fgets`, `recv`, `read`), которые достигают sink.

### 5.3 Реализация

- `hexeye/analyzer.py` — основной модуль (r2pipe + capstone) — см. код.
- `hexeye/rust/src/` — (набросок) Capstone-based быстрый проход ELF-секций для крупных бинарников.

---

## 6. Модуль 5: ApexConsole (3D Visual Dashboard)

### 6.1 Назначение

Единый центр управления. Реализация — SPA (TypeScript + Vite + Three.js + WebGL). Соединение с AegisBus через WebSocket (события ThreatEvent) и gRPC-Web (команды управления).

### 6.2 Возможности

1. **3D-топология**: узлы сети (хосты, контейнеры, honeypots) как сферы в Three.js, рёбра — линии (соединения), анимация атак — «летящие» снаряды от узла атаки к цели, пульсация у honeypot при срабатывании.
2. **Фильтрация алертов**: по severity (Critical → red, High → orange, Medium → yellow, Info → blue), по источнику, по MITRE technique. Используется HTML5 `<canvas>` + CSS-анимации.
3. **Панель управления**: кнопки — `Block IP`, `Reload eBPF probes`, `Start fuzz job`, `Spawn honeypot`, `Analyze binary`.
4. **Glassmorphism**: backdrop-filter blur, полупрозрачные панели, неоновая графика.

### 6.3 Стек

- `three` (WebGL renderer), `@react-three/fiber` (optional), `socket.io-client` или нативный WS.
- `vite` + `typescript`.
- Метрики в реальном времени: `SystemMetric` — CPU/сеть/латентность обновляются через WS.

---

## 7. Проекция на структуру репозитория

```
ApexGuard/
├── docs/TDD.md                 # этот документ
├── proto/events.proto          # схемы событий и сервисов
├── kernelshield/
│   ├── probes/kernelshield.bpf.c
│   └── agent/src/main.rs
├── pulsefuzz/
│   ├── main.go
│   └── internal/mutator/mutator.go
├── shadownet/
│   ├── honeypot/ssh_server.py
│   ├── llm/client.py
│   └── mitre/mapper.py
├── hexeye/
│   ├── analyzer.py
│   └── (rust/ — опционально)
└── apexconsole/
    ├── src/main.ts
    ├── src/topology.ts
    └── index.html
```

---

## 8. Метрики и наблюдаемость

- **Prometheus**: `/metrics` у каждого модуля — события/сек, latency p50/p99, drop counter (ring buffer), fuzz jobs, active honeypots.
- **Grafana** (опционально) — агрегированная панель.
- **Trace**: OpenTelemetry spans на границах gRPC-вызовов (трассировка инцидента от eBPF до UI).

## 9. Безопасность самой платформы

- Все gRPC-эндпоинты с mTLS (SPIFFE/SPIRE), кроме WebSocket-консоли (WSS + JWT).
- BPF-объект проверяется подписью (SHA-256) при загрузке, `bpf_obj_verify` перед attach.
- Консоль — только для авторизованных операторов (RBAC).
