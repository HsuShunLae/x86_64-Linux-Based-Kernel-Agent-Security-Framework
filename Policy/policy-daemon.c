#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf_policy.skel.h"
#include "policy_parser.h"

#define SOCK_PATH "/tmp/policy-daemon.sock"


static inline bool is_noise_syscall(__u32 nr)
{
    switch (nr) {
    case 0:   // read
    case 1:   // write
    case 3:   // close
    case 5:   // fstat
    case 8:   // lseek
    case 9:   // mmap
    case 10:  // mprotect
    case 11:  // munmap
    case 12:  // brk
    case 13:  // rt_sigaction
    case 14:  // rt_sigprocmask
    case 15:  // rt_sigreturn
    case 17:  // pread64
    case 18:  // pwrite64
    case 19:  // readv
    case 20:  // writev
    case 21:  // access
    case 23:  // select
    case 24:  // sched_yield
    case 25:  // mremap
    case 26:  // msync
    case 27:  // mincore
    case 28:  // madvise
    case 35:  // nanosleep
    case 39:  // getpid
    case 60:  // exit
    case 89: //readlink
    case 110: // getppid
    case 186: // gettid
    case 191: // getxattr
    case 192: // lgetxattr
    case 228: // clock_gettime
    case 230: // clock_nanosleep
    case 231: // exit_group
    case 332: //statx
        return true;
    default:
        return false;
    }
}



static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void bump_memlock_rlimit_or_die(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(1);
    }
}

struct policy_config {
    __u32 controller_pid;
    __u32 target_pid;
};

struct syscall_pair {
    __u32 from;
    __u32 to;
};

struct violation {
    __u32 pid;
    __u32 tid;
    __u32 syscall;
    __u32 from;
    __u64 count;
    __u64 limit;
};

struct daemon_request {
    __u32 target_pid;
    char  policy_path[512];
};

static int make_server_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }

    unlink(SOCK_PATH);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind(SOCK_PATH)");
        close(fd);
        return -1;
    }

    //deamon access to unprivilleged users
    if (chmod(SOCK_PATH, 0666) != 0) {
        perror("chmod(SOCK_PATH)");
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int read_full(int fd, void *buf, size_t len)
{
    size_t off = 0;
    unsigned char *p = (unsigned char *)buf;

    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int clear_last_violation(struct ebpf_policy_bpf *skel)
{
    __u32 key0 = 0;
    struct violation zero;
    memset(&zero, 0, sizeof(zero));

    if (bpf_map_update_elem(bpf_map__fd(skel->maps.last_violation), &key0, &zero, BPF_ANY) != 0) {
        perror("bpf_map_update_elem(last_violation=zero)");
        return -1;
    }
    return 0;
}

static int configure_bpf_maps(struct ebpf_policy_bpf *skel,
                              const struct policy_result *policy,
                              pid_t target_pid)
{
    __u32 key0 = 0;

    struct policy_config cfg = {
        .controller_pid = (__u32)getpid(),
        .target_pid     = (__u32)target_pid
    };

    if (bpf_map_update_elem(bpf_map__fd(skel->maps.policy_cfg), &key0, &cfg, BPF_ANY) != 0) {
        perror("bpf_map_update_elem(policy_cfg)");
        return -1;
    }

    // syscall limits 
    for (size_t i = 0; i < policy->syscall_count_cnt; i++) {
	    __u32 nr = (__u32)policy->syscall_counts[i].syscall;
	    __u64 limit;

	    if (is_noise_syscall(nr)) {
	    	continue;
	    } else {
		limit = (__u64)policy->syscall_counts[i].max_count;
	    }
	    if (bpf_map_update_elem(bpf_map__fd(skel->maps.syscall_limit), &nr, &limit, BPF_ANY) != 0) {

		perror("bpf_map_update_elem(syscall_limit)");
		return -1;
	    }
	}

    // allowed transitions
    for (size_t i = 0; i < policy->transition_cnt; i++) {
        __u32 from = policy->transitions[i].from;

        for (size_t j = 0; j < policy->transitions[i].to_cnt; j++) {
            struct syscall_pair k = {
                .from = from,
                .to   = policy->transitions[i].to[j]
            };
            __u8 one2 = 1;

            if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_transitions), &k, &one2, BPF_ANY) != 0) {
                perror("bpf_map_update_elem(allowed_transitions)");
                return -1;
            }
        }
    }

    // Ensure not log stale data from a previous target
    (void)clear_last_violation(skel);

    return 0;
}

static void poll_violations_and_enforce(struct ebpf_policy_bpf *skel, pid_t active_target)
{
    __u32 key0 = 0;
    struct violation vio;
    memset(&vio, 0, sizeof(vio));

    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.last_violation), &key0, &vio) != 0) {
        return; 
    }

    if (vio.pid == 0) return;

    fprintf(stderr, "[policy-daemon] VIOLATION pid=%u tid=%u syscall=%u from=%u count=%llu limit=%llu\n", vio.pid, vio.tid, vio.syscall, vio.from, (unsigned long long)vio.count, (unsigned long long)vio.limit);

    (void)clear_last_violation(skel);
}

static void handle_one_request(int srv_fd, struct ebpf_policy_bpf *skel, pid_t *active_target)
{
    int cfd = accept(srv_fd, NULL, NULL);
    if (cfd < 0) {
        if (errno == EINTR) return;
        perror("accept");
        return;
    }

    struct daemon_request req;
    memset(&req, 0, sizeof(req));

    if (read_full(cfd, &req, sizeof(req)) != 0) {
        fprintf(stderr, "[policy-daemon] bad request\n");
        close(cfd);
        return;
    }

    close(cfd);

    // Parse policy JSON 
    struct policy_result policy;
    if (parse_policy_json(req.policy_path, &policy) != 0) {
        fprintf(stderr, "[policy-daemon] policy parse failed: %s\n", req.policy_path);
        return;
    }

    if (configure_bpf_maps(skel, &policy, (pid_t)req.target_pid) != 0) {
        fprintf(stderr, "[policy-daemon] failed to configure BPF maps for pid=%u\n", req.target_pid);
        return;
    }

    *active_target = (pid_t)req.target_pid;
    fprintf(stdout, "[policy-daemon] supervising pid=%d policy=%s\n", *active_target, req.policy_path);
}

int main(void)
{
    setup_signals();
    bump_memlock_rlimit_or_die();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct ebpf_policy_bpf *skel = ebpf_policy_bpf__open();
    if (!skel) {
        fprintf(stderr, "[policy-daemon] ebpf_policy_bpf__open failed\n");
        return 1;
    }

    if (ebpf_policy_bpf__load(skel)) {
        fprintf(stderr, "[policy-daemon] ebpf_policy_bpf__load failed\n");
        ebpf_policy_bpf__destroy(skel);
        return 1;
    }

    if (ebpf_policy_bpf__attach(skel)) {
        fprintf(stderr, "[policy-daemon] ebpf_policy_bpf__attach failed\n");
        ebpf_policy_bpf__destroy(skel);
        return 1;
    }

    int srv = make_server_socket();
    if (srv < 0) {
        ebpf_policy_bpf__destroy(skel);
        return 1;
    }

    fprintf(stdout, "[policy-daemon] started pid=%d socket=%s\n", getpid(), SOCK_PATH);

    pid_t active_target = -1;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv, &rfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int rc = select(srv + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (rc > 0 && FD_ISSET(srv, &rfds)) {
            handle_one_request(srv, skel, &active_target);
        }

        poll_violations_and_enforce(skel, active_target);
    }

    ebpf_policy_bpf__detach(skel);
    close(srv);
    unlink(SOCK_PATH);
    ebpf_policy_bpf__destroy(skel);

    fprintf(stdout, "[policy-daemon] exiting\n");
    return 0;
}

