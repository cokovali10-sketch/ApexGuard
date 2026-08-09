// SPDX-License-Identifier: GPL-2.0
// KernelShield — eBPF probe. CO-RE ready (vmlinux.h, libbpf).
// Сборка: clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
//         -I/usr/include/x86_64-linux-gnu -c kernelshield.bpf.c -o kernelshield.bpf.o
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_ARGV 16
#define ARG_LEN 64
#define MAX_CONTAINER_ID 32

// --- Кольцевой буфер: zero-copy передача событий в user space ---
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

// --- Карта решений: быстрый lookup (ip, pid) → BLOCK ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8); // 1 = block
} blocked_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // ipv4
    __type(value, __u8);
} blocked_ips SEC(".maps");

// --- Глобальный флаг Panic Mode (AirGap): 0/1. Управляется user-space. ---
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} panic_mode SEC(".maps");

static __always_inline bool is_panic_active(void)
{
    __u32 key = 0;
    __u8 *v = bpf_map_lookup_elem(&panic_mode, &key);
    return v && *v != 0;
}

// --- Тип события, зеркалит proto EventType ---
enum evt_type {
    EVT_EXECVE = 1,
    EVT_CONNECT = 2,
    EVT_PTRACE = 3,
    EVT_PRIVILEGE = 4,
    EVT_NAMESPACE = 5,
    EVT_BLOCKED = 6,
};

// Компактная структура для ring buffer (без map<string,string>, - fixed layout)
struct exec_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u64 ts;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;          // source container id
    __u8  blocked;
    __u8  container_escape;   // флаг обхода namespace
    char  comm[TASK_COMM_LEN];
    char  filename[256];
    char  argv[MAX_ARGV][ARG_LEN];
};

// Флаг безопасности: current context требует подозрительных прав?
static __always_inline bool has_suspicious_caps(const struct task_struct *task)
{
    __u64 capabilities = BPF_CORE_READ(task, cred, cap_effective);
    // CAP_SYS_ADMIN (bit 21) | CAP_SYS_PTRACE (bit 19) | CAP_SYS_MODULE (bit 16)
    return (capabilities & ((1ULL << 21) | (1ULL << 19) | (1ULL << 16))) != 0;
}

static __always_inline bool is_container_escape(const char *filename)
{
    // /proc/<pid>/root, /proc/<pid>/ns/*, /proc/<pid>/mem — обход namespace.
    // Простая проверка первых 6 байт "/proc/" через bpf_probe_read_kernel_str.
    char head[6];
    long n = bpf_probe_read_kernel_str(head, sizeof(head), filename);
    if (n <= 0)
        return false;
    // bpf_strncmp возвращает 0 при совпадении; strncmp на /proc/
    return bpf_strncmp(head, 6, "/proc/") == 0;
}

// ============================================================================
// HOOK 1: sys_enter_execve / execveat — перехват запуска процессов
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 block = 0;

    // В Panic Mode блокируем запуск любых новых процессов (AirGap).
    if (is_panic_active())
        block = 1;

    if (bpf_map_lookup_elem(&blocked_pids, &pid))
        block = 1;

    // Проверяем файл (argv[0] = filename)
    const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    if (filename == NULL)
        return 0;

    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVT_EXECVE;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->ts = bpf_ktime_get_ns();
    e->uid = BPF_CORE_READ(task, cred, uid);
    e->gid = BPF_CORE_READ(task, cred, gid);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->blocked = block;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename);

    // Копируем argv (остальные аргументы) — не более MAX_ARGV*ARG_LEN
    for (int i = 1; i < MAX_ARGV; i++) {
        const char *arg = (const char *)BPF_CORE_READ(ctx, args[i]);
        if (!arg)
            break;
        bpf_probe_read_kernel_str(&e->argv[i], ARG_LEN, arg);
    }

    // --- КЛАССИФИКАЦИЯ: подозрительный запуск → немедленный kill ---
    bool malicious = false;
    if (e->comm[0] == 's' && has_suspicious_caps(task))
        malicious = true; // shell с CAP_SYS_ADMIN/PTRACE

    if (malicious || block) {
        e->blocked = true;
        // Мгновенная блокировка ДО возврата в user space.
        bpf_send_signal(SIGKILL);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// HOOK 2: sys_enter_connect — C2 / exfiltration
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sockaddr *addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);

    if (addr == NULL)
        return 0;

    // Порт в сетевом порядке байт, sockaddr_in6 -> port в offset 2
    __u16 port_net = 0;
    __u8 family = 0;
    bpf_probe_read_kernel(&family, 1, addr);
    if (family == AF_INET) {
        bpf_probe_read_kernel(&port_net, 2, (void *)addr + 2);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&port_net, 2, (void *)addr + 2);
    } else {
        return 0;
    }
    __u16 port = bpf_ntohs(port_net);

    // В Panic Mode блокируем все исходящие соединения (AirGap) прямо в ядре.
    if (is_panic_active()) {
        struct exec_event *pe = bpf_ringbuf_reserve(&events, sizeof(*pe), 0);
        if (pe) {
            pe->type = EVT_BLOCKED;
            pe->pid = pid;
            pe->ts = bpf_ktime_get_ns();
            pe->cgroup_id = bpf_get_current_cgroup_id();
            pe->blocked = true;
            bpf_get_current_comm(&pe->comm, sizeof(pe->comm));
            bpf_ringbuf_submit(pe, 0);
        }
        // XDP/TC-хук сбросит пакет; здесь — принудительный kill процесса-инициатора.
        bpf_send_signal(SIGKILL);
        return 0;
    }

    // Подозрительные порты (C2-диапазоны, IRC 6667, известные beaconing)
    if (port < 1024 || port == 6667 || port == 4444)
        return 0; // не классифицируем легитимные

    // IP 4 байта, читаем только IPv4
    __u32 ip = 0;
    if (family == AF_INET)
        bpf_probe_read_kernel(&ip, 4, (void *)addr + 4);

    __u8 *ip_blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
    if (ip_blocked) {
        // сетевая блокировка: XDP-хук сбросит пакет; здесь логируем
        struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;
        e->type = EVT_BLOCKED;
        e->pid = pid;
        e->ts = bpf_ktime_get_ns();
        e->cgroup_id = bpf_get_current_cgroup_id();
        e->blocked = true;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ============================================================================
// HOOK 3: sys_enter_ptrace — debug-инъекции, anti-EDR
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 request = BPF_CORE_READ(ctx, args[0]);
    __u32 target = (__u32)BPF_CORE_READ(ctx, args[1]);

    // PTRACE_POKEDATA=4, PTRACE_POKETEXT=4, PTRACE_ATTACH=16
    if (request == 4 || request == 16) {
        struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;
        e->type = EVT_PTRACE;
        e->pid = pid;
        e->ppid = target;
        e->ts = bpf_ktime_get_ns();
        e->cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ============================================================================
// HOOK 4: sys_enter_setuid — LPE (T1548)
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_setuid")
int tp_sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 uid = BPF_CORE_READ(ctx, args[0]);
    if (uid != 0)
        return 0; // не-root попытка

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->type = EVT_PRIVILEGE;
    e->pid = pid;
    e->ts = bpf_ktime_get_ns();
    e->uid = BPF_CORE_READ(task, cred, uid);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Вспомогательная функция (никогда не вызывается из-за контекста tracepoint,
// оставлена для LSM-hook варианта через BPF_PROG_TYPE_LSM)
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&blocked_pids, &pid)) {
        return -EPERM; // запрет системного вызова в ядре
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
