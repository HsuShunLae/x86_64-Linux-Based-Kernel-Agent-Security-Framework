typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

typedef int                __s32;
typedef long long          __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include "ebpf_helper.h"

char LICENSE[] SEC("license") = "GPL";

#define SIGKILL 9


struct policy_config {
    __u32 controller_pid;
    __u32 target_pid;
};

struct syscall_count_key {
    __u32 pid;
    __u32 syscall;
};

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    long  id; //syscall_nr
};


struct trace_event_raw_sched_process_exit {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} policy_cfg SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_count_key);
    __type(value, __u64);
} syscall_count SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, __u64);
} syscall_limit SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} last_syscall SEC(".maps");



struct syscall_pair {
    __u32 from;
    __u32 to;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct syscall_pair);
    __type(value, __u8);
} allowed_transitions SEC(".maps");



struct violation {
    __u32 pid;
    __u32 tid;
    __u32 syscall;
    __u32 from;
    __u64 count;
    __u64 limit;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct violation);
} last_violation SEC(".maps");



static __always_inline void inc_syscall_count(__u32 pid, __u32 nr)
{
    struct syscall_count_key key = {
        .pid     = pid,
        .syscall = nr,
    };
    map_inc_percpu_u64_init(&syscall_count, &key);
}



SEC("tracepoint/raw_syscalls/sys_enter")
int on_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u32 k0 = 0;
    struct policy_config *cfg = bpf_map_lookup_elem(&policy_cfg, &k0);
    if (!cfg)
        return 0;

    if (pid == cfg->controller_pid)
        return 0;

    if (pid != cfg->target_pid)
        return 0;

    __u32 nr = ctx->id;
    
    inc_syscall_count(pid, nr);

     /* ENTRY SYSCALL CHECK */
    __u32 *p_prev = bpf_map_lookup_elem(&last_syscall, &tid);
    if (!p_prev) {
    	   bpf_map_update_elem(&last_syscall, &tid, &nr, BPF_ANY);
           return 0;
    }

     /* COUNT-BASED ENFORCEMENT */
    __u64 *limit = bpf_map_lookup_elem(&syscall_limit, &nr);
    struct syscall_count_key cnt_key = {
	    .pid     = pid,
	    .syscall = nr,
	};
    if (limit) {
	__u64 *local_cnt = bpf_map_lookup_elem(&syscall_count, &cnt_key);

        if (local_cnt && *local_cnt >= *limit + 1) {

            struct violation v = {
                .pid     = pid,
                .tid     = tid,
                .syscall = nr,
                .from    = *p_prev,
                .count   = *local_cnt,
                .limit   = *limit,
            };

            bpf_map_update_elem(&last_violation, &k0, &v, BPF_ANY);
            bpf_map_delete_elem(&last_syscall, &tid);
            bpf_map_delete_elem(&syscall_count, &cnt_key);
            bpf_send_signal(SIGKILL);
            return 0;
        }
        
    }


     /* TRANSITION CHECK*/
    if (p_prev) {
        struct syscall_pair key = {
            .from = *p_prev,
            .to   = nr,
        };

        __u8 *ok = bpf_map_lookup_elem(&allowed_transitions, &key);
        if (!ok) {
            struct violation v = {
                .pid     = pid,
                .tid     = tid,
                .syscall = nr,
                .from    = *p_prev,
                .count   = 0,
                .limit   = 0,
            };
            bpf_map_update_elem(&last_violation, &k0, &v, BPF_ANY);
            bpf_map_delete_elem(&syscall_count, &cnt_key);
        }
    }
    bpf_map_update_elem(&last_syscall, &tid, &nr, BPF_ANY);
    return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u32 k0 = 0;
    struct policy_config *cfg = bpf_map_lookup_elem(&policy_cfg, &k0);
    if (!cfg)
        return 0;

    if (pid != cfg->target_pid)
        return 0;

    /* cleanup per-thread state */
    bpf_map_delete_elem(&last_syscall, &tid);

    return 0;
}

