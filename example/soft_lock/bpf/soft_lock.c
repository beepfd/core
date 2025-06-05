// go:build ignore

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 定义看门狗告警阈值 (1秒 = 1,000,000,000 纳秒)
#define WATCHDOG_WARN_THRESHOLD (1000000000ULL) // 1秒

// 定义看门狗跟踪信息结构体（避免与内核定义冲突）
struct watchdog_tracking_info
{
    u64 last_timestamp;
    u32 touch_count;
    u32 soft_lockup_count;
    u32 hard_lockup_count;
} __attribute__((packed));

// 定义软锁定事件结构体
struct soft_lockup_event
{
    u32 cpu;
    u64 timestamp;
    u64 interval;
    u32 pid;
    char comm[16];
} __attribute__((packed));

// 确保结构体类型信息被保留在 BTF 中
struct watchdog_tracking_info *unused_watchdog_tracking_info __attribute__((unused));
struct soft_lockup_event *unused_soft_lockup_event __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct watchdog_tracking_info);
} watchdog_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("kprobe/watchdog_timer_fn")
int trace_watchdog_timer(struct pt_regs *regs)
{
    u32 cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();

    struct watchdog_tracking_info *info = bpf_map_lookup_elem(&watchdog_map, &cpu);
    if (!info)
    {
        struct watchdog_tracking_info new_info = {
            .last_timestamp = now,
            .touch_count = 0,
            .soft_lockup_count = 0,
            .hard_lockup_count = 0};
        bpf_map_update_elem(&watchdog_map, &cpu, &new_info, BPF_NOEXIST);
        return 0;
    }

    // 计算间隔时间
    u64 interval = now - info->last_timestamp;
    info->last_timestamp = now;

    // 检测异常间隔（可能的锁定）
    if (interval > WATCHDOG_WARN_THRESHOLD)
    {
        bpf_printk("Watchdog: CPU%d interval=%llu ns (potential lockup)",
                   cpu, interval);

        // 记录潜在的软锁定事件
        struct soft_lockup_event event = {
            .cpu = cpu,
            .timestamp = now,
            .interval = interval,
            .pid = bpf_get_current_pid_tgid() >> 32,
        };
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        bpf_perf_event_output(regs, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
    }

    return 0;
}
