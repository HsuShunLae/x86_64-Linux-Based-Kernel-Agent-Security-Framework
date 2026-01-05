#include "policy_parser.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int parse_policy_json(
    const char *path,
    struct policy_result *out
) {
    json_t *root;
    json_error_t err;

    out->allowed_cnt = 0;
    out->transition_cnt = 0;

    root = json_load_file(path, 0, &err);
    if (!root) {
        fprintf(stderr, "JSON parse error: %s (line %d)\n",
                err.text, err.line);
        return -1;
    }

    /* -------- allowed_syscalls -------- */
    json_t *allowed = json_object_get(root, "allowed_syscalls");
    if (!json_is_array(allowed))
        goto fail;

    size_t n_allowed = json_array_size(allowed);
    
    for (size_t i = 0; i < n_allowed; i++) {
        json_t *v = json_array_get(allowed, i);
        if (!json_is_integer(v))
            goto fail;
        out->allowed_syscalls[i] = (int)json_integer_value(v);
    }
    out->allowed_cnt = n_allowed;

    
    
    /* syscall_counts */
	json_t *counted = json_object_get(root, "syscall_counts");
	if (!json_is_array(counted))
	    goto fail;

	size_t n_counted = json_array_size(counted);

	out->syscall_count_cnt = 0;

	for (size_t i = 0; i < n_counted; i++) {
	    json_t *pair = json_array_get(counted, i);
	    if (!json_is_array(pair) || json_array_size(pair) != 2)
		goto fail;

	    json_t *sys_v = json_array_get(pair, 0);
	    json_t *cnt_v = json_array_get(pair, 1);

	    if (!json_is_integer(sys_v) || !json_is_integer(cnt_v))
		goto fail;

	    out->syscall_counts[out->syscall_count_cnt].syscall = (int)json_integer_value(sys_v);

	    out->syscall_counts[out->syscall_count_cnt].max_count = (int)json_integer_value(cnt_v);

	    out->syscall_count_cnt++;
	}


    /* allowed_transitions */
    json_t *trans = json_object_get(root, "allowed_transitions");
    if (!json_is_object(trans))
        goto fail;

    const char *key;
    json_t *val;

    json_object_foreach(trans, key, val) {

        char *end;
        errno = 0;
        long from = strtol(key, &end, 10);
        if (errno || *end != '\0')
            goto fail;

        if (!json_is_array(val))
            goto fail;

        struct transition_entry *e =
            &out->transitions[out->transition_cnt++];

        e->from = (int)from;
        e->to_cnt = 0;

        size_t n_to = json_array_size(val);

        for (size_t i = 0; i < n_to; i++) {
            json_t *to_v = json_array_get(val, i);
            if (!json_is_integer(to_v))
                goto fail;
            e->to[e->to_cnt++] = (int)json_integer_value(to_v);
        }
    }

    json_decref(root);
    return 0;

fail:
    fprintf(stderr, "Invalid json format\n");
    json_decref(root);
    return -1;
}
