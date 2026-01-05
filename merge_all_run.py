#!/usr/bin/env python3

import json
import argparse
import sys


def merge_policies(policy_a: dict, policy_b: dict) -> dict:

    allowed = sorted(
        set(policy_a.get("allowed_syscalls", [])) |
        set(policy_b.get("allowed_syscalls", []))
    )
    allowed_set = set(allowed)


    entry_syscalls = sorted(
        set(policy_a.get("entry_syscalls", [])) |
        set(policy_b.get("entry_syscalls", []))
    )
    entry_syscalls = [sc for sc in entry_syscalls if sc in allowed_set]


    merged_transitions = {}

    def merge_transition_map(trans_map):
        for src, dsts in trans_map.items():
            src_i = int(src)
            if src_i not in allowed_set:
                continue

            valid_dsts = [d for d in dsts if d in allowed_set]
            if not valid_dsts:
                continue

            merged_transitions.setdefault(str(src_i), set()).update(valid_dsts)

    merge_transition_map(policy_a.get("allowed_transitions", {}))
    merge_transition_map(policy_b.get("allowed_transitions", {}))

    merged_transitions = {
        src: sorted(dsts)
        for src, dsts in merged_transitions.items()
    }


    merged_transition_counts = {}
    for policy in (policy_a, policy_b):
        for frm, to, cnt in policy.get("transition_counts", []):
            if frm in allowed_set and to in allowed_set:
                merged_transition_counts[(frm, to)] = max(merged_transition_counts.get((frm, to), 0),cnt)

    merged_transition_counts = [
        [frm, to, cnt]
        for (frm, to), cnt in sorted(merged_transition_counts.items())
    ]


    merged_syscall_counts = {}
    for policy in (policy_a, policy_b):
        for nr, cnt in policy.get("syscall_counts", []):
            if nr in allowed_set:
                merged_syscall_counts[nr] = max(merged_syscall_counts.get(nr, 0),cnt)

    merged_syscall_counts = [
        [nr, cnt]
        for nr, cnt in sorted(merged_syscall_counts.items())
    ]

    return {
        "allowed_syscalls": allowed,
        "entry_syscalls": entry_syscalls,
        "allowed_transitions": merged_transitions,
        "transition_counts": merged_transition_counts,
        "syscall_counts": merged_syscall_counts,
    }


def load_json(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"[ERROR] Failed to load {path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Merge syscall policies: union allowlist, union+pruned FSM"
    )
    parser.add_argument("--policy-a", required=True, help="Primary policy JSON")
    parser.add_argument("--policy-b", required=True, help="Secondary policy JSON")
    parser.add_argument("--out", required=True, help="Output merged policy JSON")

    args = parser.parse_args()

    policy_a = load_json(args.policy_a)
    policy_b = load_json(args.policy_b)

    merged = merge_policies(policy_a, policy_b)

    try:
        with open(args.out, "w") as f:
            json.dump(merged, f, indent=2, sort_keys=True)
    except Exception as e:
        sys.exit(f"[ERROR] Failed to write output: {e}")

    print(f"[OK] Merged policy written to {args.out}")
    print(f"     allowed_syscalls [new]: {len(merged['allowed_syscalls'])}")
    print(f"     entry_syscalls   [new]: {len(merged['entry_syscalls'])}")
    print(f"     transitions      [new]: {len(merged['transition_counts'])}")


if __name__ == "__main__":
    main()
