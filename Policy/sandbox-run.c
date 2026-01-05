#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/types.h>

#include "policy_parser.h"
#include "seccomp_launcher.h"

#define SOCK_PATH "/tmp/policy-daemon.sock"

struct daemon_request {
    __u32 target_pid;
    char  policy_path[512];
};

static int notify_daemon(pid_t target_pid, const char *policy_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect(policy-daemon)");
        close(fd);
        return -1;
    }

    struct daemon_request req;
    memset(&req, 0, sizeof(req));
    req.target_pid = (__u32)target_pid;
    strncpy(req.policy_path, policy_path, sizeof(req.policy_path) - 1);

    size_t to_write = sizeof(req);
    const unsigned char *p = (const unsigned char *)&req;
    while (to_write > 0) {
        ssize_t n = write(fd, p, to_write);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("write(daemon_request)");
            close(fd);
            return -1;
        }
        p += (size_t)n;
        to_write -= (size_t)n;
    }

    close(fd);
    return 0;
}

static void drop_privs_or_die(void)
{
    gid_t rgid = getgid();
    uid_t ruid = getuid();

    if (setgid(rgid) != 0) {
        perror("setgid");
        _exit(1);
    }
    if (setuid(ruid) != 0) {
        perror("setuid");
        _exit(1);
    }
}

static pid_t launch_target_with_seccomp(const struct policy_result *policy, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // drop privileges 
        drop_privs_or_die();

        // Install seccomp allowlist before exec
        if (install_seccomp_policy(policy->allowed_syscalls, policy->allowed_cnt) != 0) {
            fprintf(stderr, "[sandbox-run] seccomp install failed\n");
            _exit(1);
        }

        execvp(argv[0], argv);
        perror("execvp");
        _exit(1);
    }

    return pid;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <policy.json> <program> [args...]\n", argv[0]);
        return 1;
    }

    const char *policy_path = argv[1];
    /* Enforce absolute path */
    if (policy_path[0] == '.') {
        fprintf(stderr,"[sandbox-run] ERROR: policy path must be absolute: %s\n", policy_path);
        return 1;
    }
    char *const *target_argv = &argv[2];

    struct policy_result policy;
    if (parse_policy_json(policy_path, &policy) != 0) {
        fprintf(stderr, "[sandbox-run] Failed to parse policy JSON: %s\n", policy_path);
        return 1;
    }

    pid_t child = launch_target_with_seccomp(&policy, (char *const *)target_argv);
    if (child < 0) return 1;

    if (notify_daemon(child, policy_path) != 0) {
        fprintf(stderr, "[sandbox-run] WARNING: could not notify policy-daemon (pid=%d).\nTarget still running with seccomp only.\n", child);
    } else {
        fprintf(stdout, "[sandbox-run] daemon notified: target pid=%d policy=%s\n", child, policy_path);
    }

    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        fprintf(stdout, "[sandbox-run] target exited: code=%d\n", code);
        return code;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGSYS) {
          fprintf(stdout, "[sandbox-run] target terminated by seccomp policy (SIGSYS)\n");
      } else if (sig == SIGKILL) {
          fprintf(stdout, "[sandbox-run] target terminated by policy-daemon enforcement (SIGKILL)\n");
      } else {
          fprintf(stdout, "[sandbox-run] target killed by signal=%d\n", sig);
      }

        return 128 + sig;
    }

    fprintf(stdout, "[sandbox-run] target ended (unknown status)\n");
    return 1;
}

