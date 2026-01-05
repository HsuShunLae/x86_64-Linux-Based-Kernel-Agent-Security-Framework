#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <grp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dynamic_tracer.skel.h"


#define MAX_SYSCALL_NR   512
#define MAX_TRANSITIONS  65536
#define NO_SYSCALL ((__u32)-1)


static volatile sig_atomic_t exiting = 0;
static int target_pid = 0;

static __u64 syscall_count[MAX_SYSCALL_NR];
static bool  seen_syscall[MAX_SYSCALL_NR];
static bool  entry_flags[MAX_SYSCALL_NR];
static bool  adj[MAX_SYSCALL_NR][MAX_SYSCALL_NR];

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u32 syscall_id;
    __u32 prev_syscall_id;
};

struct config {
    __u32 target_pid;
    __u32 exclude_pid;
};


struct transition {
    __u32 from;
    __u32 to;
    __u64 count;
};


static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    const struct event *e = data;

    /* Defensive bounds check */
    if (e->syscall_id >= MAX_SYSCALL_NR)
        return 0;

    if (target_pid && e->pid != (unsigned)target_pid)
        return 0;

    /* Entry syscall detection */
    if (e->prev_syscall_id == NO_SYSCALL)
        entry_flags[e->syscall_id] = true;

    return 0;
}

static int write_json(struct dynamic_tracer_bpf *skel,
                      const char *json_path)
{
    FILE *f = fopen(json_path, "w");
    if (!f) {
        perror("fopen");
        return -1;
    }

    int sys_fd = bpf_map__fd(skel->maps.syscall_counts);
    int tr_fd  = bpf_map__fd(skel->maps.transitions);

    struct transition transitions[MAX_TRANSITIONS];
    size_t n_tr = 0;

    memset(syscall_count, 0, sizeof(syscall_count));
    memset(seen_syscall, 0, sizeof(seen_syscall));
    memset(adj, 0, sizeof(adj));

    /* syscall counts */
    {
        __u32 key, next;
        __u64 val;
        bool first = true;

        while (bpf_map_get_next_key(sys_fd,
                first ? NULL : &key, &next) == 0) {

            if (next < MAX_SYSCALL_NR &&
                bpf_map_lookup_elem(sys_fd, &next, &val) == 0) {

                syscall_count[next] = val;
                seen_syscall[next]  = true;
            }
            key = next;
            first = false;
        }
    }

    /* transitions */
    {
        struct { __u32 from; __u32 to; } key, next;
        __u64 val;
        bool first = true;

        while (bpf_map_get_next_key(tr_fd,
                first ? NULL : &key, &next) == 0) {

            if (bpf_map_lookup_elem(tr_fd, &next, &val) == 0 &&
                n_tr < MAX_TRANSITIONS) {

                transitions[n_tr++] = (struct transition){
                    .from  = next.from,
                    .to    = next.to,
                    .count = val,
                };

                if (next.from < MAX_SYSCALL_NR &&
                    next.to   < MAX_SYSCALL_NR)
                    adj[next.from][next.to] = true;
            }
            key = next;
            first = false;
        }
    }

    /* JSON output */
    fprintf(f, "{\n");

    /* allowed_syscalls */
    fprintf(f, "  \"allowed_syscalls\": [\n");
    bool first = true;
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (seen_syscall[i]) {
            if (!first) fprintf(f, ",\n");
            fprintf(f, "    %d", i);
            first = false;
        }
    }
    fprintf(f, "\n  ],\n");

    /* entry_syscalls */
    fprintf(f, "  \"entry_syscalls\": [\n");
    first = true;
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (entry_flags[i]) {
            if (!first) fprintf(f, ",\n");
            fprintf(f, "    %d", i);
            first = false;
        }
    }
    fprintf(f, "\n  ],\n");
    
    /* grouped allowed_transitions */
    fprintf(f, "  \"allowed_transitions\": {\n");
    bool first_from = true;

    for (int from = 0; from < MAX_SYSCALL_NR; from++) {
        bool has = false;
        for (int to = 0; to < MAX_SYSCALL_NR; to++)
            if (adj[from][to]) { has = true; break; }

        if (!has) continue;

        if (!first_from) fprintf(f, ",\n");
        fprintf(f, "    \"%d\": [", from);

        bool first_to = true;
        for (int to = 0; to < MAX_SYSCALL_NR; to++) {
            if (adj[from][to]) {
                if (!first_to) fprintf(f, ", ");
                fprintf(f, "%d", to);
                first_to = false;
            }
        }
        fprintf(f, "]");
        first_from = false;
    }
    fprintf(f, "\n  },\n");

    /* transition_counts */
    fprintf(f, "  \"transition_counts\": [\n");
    for (size_t i = 0; i < n_tr; i++) {
        fprintf(f,
            "    [%u, %u, %llu]%s\n",
            transitions[i].from,
            transitions[i].to,
            (unsigned long long)transitions[i].count,
            (i + 1 < n_tr) ? "," : ""
        );
    }
    fprintf(f, "  ],\n");

    /* syscall_counts */
    fprintf(f, "  \"syscall_counts\": [\n");
    first = true;
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (seen_syscall[i]) {
            if (!first) fprintf(f, ",\n");
            fprintf(f, "    [%d, %llu]",
                    i, (unsigned long long)syscall_count[i]);
            first = false;
        }
    }    
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    uid_t drop_uid = getuid();
    gid_t drop_gid = getgid();

    char *sudo_uid = getenv("SUDO_UID");
    char *sudo_gid = getenv("SUDO_GID");

    if (sudo_uid && sudo_gid) {
	drop_uid = (uid_t)atoi(sudo_uid);
	drop_gid = (gid_t)atoi(sudo_gid);
    }
    struct dynamic_tracer_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    pid_t child_pid = -1;
    const char *json_path = NULL;
    int err = 0;
    int cmd_index = 1;
    bool use_existing_pid = false;

    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s --out <json> --pid <PID>\n"
            "  %s --out <json> <prog> [args...]\n",
            argv[0], argv[0]);
        return 1;
    }
    
    while (cmd_index < argc) {
        if (!strcmp(argv[cmd_index], "--pid")) {
            if (++cmd_index >= argc) return 1;
            target_pid = atoi(argv[cmd_index]);
            use_existing_pid = true;
        } else if (!strcmp(argv[cmd_index], "--out")) {
            if (++cmd_index >= argc) return 1;
            json_path = argv[cmd_index];
        } else {
            break;
        }
        cmd_index++;
    }

    if (!json_path) {
        fprintf(stderr, "Missing --out <json>\n");
        return 1;
    }

    if (!use_existing_pid && cmd_index >= argc) {
        fprintf(stderr, "Missing program to execute\n");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = dynamic_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (dynamic_tracer_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    if (dynamic_tracer_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    struct config cfg = {
        .exclude_pid = (unsigned)getpid(),
    };
    __u32 cfg_key = 0;

    if (!use_existing_pid) {
        child_pid = fork();
        if (child_pid < 0) {
            perror("fork");
            goto cleanup;
        }

        if (child_pid == 0) {
            if (setgroups(0, NULL) != 0 ||
		    setgid(drop_gid) != 0 ||
		    setuid(drop_uid) != 0) {
		    perror("drop privileges");
		    _exit(1);
		}

	    if (setuid(0) == 0) {
		    fprintf(stderr, "Privilege drop failed\n");
		    _exit(1);
		}
	    execvp(argv[cmd_index], &argv[cmd_index]);
            perror("execvp");
            _exit(1);
        }

        target_pid = child_pid;
    }

    cfg.target_pid = (unsigned)target_pid;

    if (bpf_map_update_elem(
            bpf_map__fd(skel->maps.config_map),
            &cfg_key, &cfg, 0) != 0) {
        perror("bpf_map_update_elem(config_map)");
        goto cleanup;
    }

    printf("Tracing PID=%d\n", target_pid);

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (!exiting) {
        int r = ring_buffer__poll(rb, 100);
        if (r < 0 && r != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", r);
            break;
        }

        if (!use_existing_pid && child_pid > 0) {
            int status;
            if (waitpid(child_pid, &status, WNOHANG) == child_pid)
                break;
        }
    }

    dynamic_tracer_bpf__detach(skel);

    if (write_json(skel, json_path) != 0)
        fprintf(stderr, "Failed to write JSON profile\n");

cleanup:
    ring_buffer__free(rb);
    dynamic_tracer_bpf__destroy(skel);
    return err;
}

