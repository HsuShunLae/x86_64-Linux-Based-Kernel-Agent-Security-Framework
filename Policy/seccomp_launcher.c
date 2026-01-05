#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include "seccomp_launcher.h"


/* build seccomp filter */
static struct sock_fprog make_filter(const int *allowed, size_t n)
{
    size_t max_ins = 3 + 1 + n * 2 + 1;

    struct sock_filter *f = calloc(max_ins, sizeof(struct sock_filter));
    if (!f) {
        perror("calloc");
        exit(1);
    }

    size_t pc = 0;

    /* arch check */
    f[pc++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));

    f[pc++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);

    f[pc++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* load syscall number */
    f[pc++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    /* allow list */
    for (size_t i = 0; i < n; i++) {
        f[pc++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, allowed[i], 0, 1);

        f[pc++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }

    /* default: kill */
    f[pc++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    return (struct sock_fprog){
        .len = (unsigned short)pc,
        .filter = f
    };
}

static void install_filter(struct sock_fprog *prog)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("PR_SET_NO_NEW_PRIVS");
        exit(1);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)) {
        perror("PR_SET_SECCOMP");
        exit(1);
    }
}

int install_seccomp_policy(const int *allowed, size_t n)
{
    struct sock_fprog prog = make_filter(allowed, n);
    install_filter(&prog);

    /* safe to free after installation for TOCTOU vuln*/
    free(prog.filter);

    return 0;
}


