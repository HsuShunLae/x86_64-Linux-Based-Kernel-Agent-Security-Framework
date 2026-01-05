typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

typedef int                __s32;


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#define NO_SYSCALL ((__u32)-1)

char LICENSE[] SEC("license") = "GPL";

struct config {
    __u32 target_pid;   
    __u32 exclude_pid;  
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");




struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    long  id; //syscall_nr
    long  args[6];
};


struct trace_event_raw_sched_process_exit {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
};

// Transition 
struct syscall_pair {
    __u32 from;
    __u32 to;
};


// Event sent to user space 
struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 syscall_id;
    __u32 prev_syscall_id;
};


// Defining Maps

// Ring buffer for streaming events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");

// Last syscall per PID, for transition tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // pid
    __type(value, __u32); // last syscall id
} last_syscall SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syscall_pair);
    __type(value, __u64);
} transitions SEC(".maps");

// Per-syscall counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);  // syscall id
    __type(value, __u64);
} syscall_counts SEC(".maps");



// HELPER for map state management (lookup/update/delete)
static __always_inline __u64 *map_lookup_u64(void *map, const void *key)
{
    return (__u64 *)bpf_map_lookup_elem(map, key);
}

static __always_inline int map_update_u64(void *map,
                                          const void *key,
                                          const __u64 *value,
                                          __u64 flags)
{
    return bpf_map_update_elem(map, key, value, flags);
}

static __always_inline int map_delete_key(void *map, const void *key)
{
    return bpf_map_delete_elem(map, key);
}

// "Increment counter" helper.
static __always_inline void map_inc_counter_u64(void *map, const void *key)
{
    __u64 *val = map_lookup_u64(map, key);
    __u64 init = 1;

    if (!val) {
        map_update_u64(map, key, &init, BPF_ANY);
    } else {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline void inc_syscall_count(__u32 id)
{
    map_inc_counter_u64(&syscall_counts, &id);
}

static __always_inline void inc_transition(__u32 from, __u32 to)
{
    struct syscall_pair key = {
        .from = from,
        .to   = to,
    };
    map_inc_counter_u64(&transitions, &key);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32; // extracting process id
    __u32 tid = (__u32)pid_tgid; //extracting thread id
    __u32 curr_id = (__u32)ctx->id; //extracting syscall

    // Load config 
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u32 target_pid = 0;
    __u32 exclude_pid = 0;

    if (cfg) {
        target_pid = cfg->target_pid;
        exclude_pid = cfg->exclude_pid;
    }

    // Exclude tracer itself
    if (exclude_pid && pid == exclude_pid)
        return 0;

    // target filter
    if (target_pid && pid != target_pid)
        return 0;

    // Transition tracking
    __u32 *prevp = bpf_map_lookup_elem(&last_syscall, &pid);
    __u32 prev_id = NO_SYSCALL;

    if (prevp) {
        prev_id = *prevp;
        if (prev_id != NO_SYSCALL) {
            inc_transition(prev_id, curr_id);
        }
    }

    // Update last syscall
    bpf_map_update_elem(&last_syscall, &pid, &curr_id, BPF_ANY);

    // Count syscall usage
    inc_syscall_count(curr_id);

    // Emit event
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->syscall_id = curr_id;
    e->prev_syscall_id = prev_id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Remove per-PID temporal state */
    bpf_map_delete_elem(&last_syscall, &pid);

    return 0;
}

