#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <stddef.h>


#define MAX_SYSCALLS     512
#define MAX_TRANSITIONS  512
#define MAX_TO_SYSCALLS  64
#define MAX_COUNTED_SYSCALLS 128


struct transition_entry {
    int from;
    int to[MAX_TO_SYSCALLS];
    size_t to_cnt;
};

struct syscall_count_entry {
    int syscall;
    int max_count;
};

struct policy_result {
    int allowed_syscalls[MAX_SYSCALLS];
    size_t allowed_cnt;

    int entry_syscall;
    
    struct syscall_count_entry syscall_counts[MAX_COUNTED_SYSCALLS];
    size_t syscall_count_cnt;

    struct transition_entry transitions[MAX_TRANSITIONS];
    size_t transition_cnt;
};


int parse_policy_json(
    const char *path,
    struct policy_result *out
);

#endif 
