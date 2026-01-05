#ifndef EBPF_HELPER_H
#define EBPF_HELPER_H

#include <bpf/bpf_helpers.h>


static __always_inline __u64 * map_lookup_u64(void *map, const void *key)
{
    return bpf_map_lookup_elem(map, key);
}

static __always_inline int map_update_u64(void *map, const void *key, const __u64 *value)
{
    return bpf_map_update_elem(map, key, value, BPF_ANY);
}

static __always_inline int map_delete_key(void *map, const void *key)
{
    return bpf_map_delete_elem(map, key);
}

static __always_inline void map_inc_percpu_u64_init(void *map, const void *key)
{
    __u64 init = 1;
    __u64 *val = bpf_map_lookup_elem(map, key);

    if (val) {
        (*val)++;
    } else {
        bpf_map_update_elem(map, key, &init, BPF_ANY);
    }
}

#endif 

