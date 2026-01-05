#!/usr/bin/env python3
import sys
import json
import hashlib
from pathlib import Path
import csv

import ldd
import syscall_finder



# CACHE SETUP

CACHE_DIR = Path("/home/hsu/project_final/static_tracer/.cache/syscalls")
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def make_cache_key(path: Path):
    p = path.resolve()
    stat = p.stat()
    key_string = f"{p}:{stat.st_size}:{stat.st_mtime}"
    return hashlib.sha256(key_string.encode()).hexdigest()


def cache_path_for(path: Path):
    key = make_cache_key(path)
    return CACHE_DIR / f"{key}.json"



# CACHED SYSCALL COLLECTION
def collect_syscalls_with_cache(binary_path: Path):

    cache_file = cache_path_for(binary_path)

    # Cache hit
    if cache_file.exists():
        try:
            with cache_file.open() as f:
                cached = json.load(f)
            return set(cached.get("syscalls", []))
        except Exception:
            pass  # fall through to recompute if cache file is corrupted

    # Cache miss, perform analysis
    print(f"[cache miss] analyzing {binary_path}")

    try:
        sites = syscall_finder.collect_syscalls(str(binary_path))
        used = {int(nr) for (_, nr) in sites if isinstance(nr, int)}
    except Exception as e:
        print(f"[-] Raw syscall collection failed for {binary_path}: {e}")
        used = set()

    # Store in cache
    try:
        with cache_file.open("w") as f:
            json.dump({"syscalls": sorted(used)}, f)
    except Exception as e:
        print(f"[cache write failed] {e}")

    return used



# DEPENDENCY DISCOVERY

def collect_dependencies(binary_path: str):
    deps = ldd.get_dependencies(binary_path)
    if not isinstance(deps, (list, set, tuple)):
        raise RuntimeError("Unexpected ldd output format")
    return set(deps)

def get_blocked_syscalls(syscalls):
    blocked = []
    with open('/home/hsu/project_final/static_tracer/syscalls_x86_64_from_tbl.csv') as csvfile:
        tbl = csv.reader(csvfile)
        for row in tbl:
            if int(row[0]) not in syscalls:
                blocked.append(row[1])
    return blocked


# Main Analysis Pipeline
def analyze_binary(binary_path: Path):
    # Collect dependencies via ldd
    files = collect_dependencies(str(binary_path))
    # Include the binary itself
    files.add(str(binary_path))

    all_used_syscalls = set()

    # Analyze each dependency with caching
    for dep in files:
        used = collect_syscalls_with_cache(Path(dep))
        all_used_syscalls |= used

    blocked = get_blocked_syscalls(all_used_syscalls)
    print("[-] Total Blocked syscalls: ", len(blocked))

    # Final result, ONLY allowed syscall numbers
    return {
        "allowed_syscalls": sorted(all_used_syscalls)
    }


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <binary> <output.json>")
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if not binary_path.exists() or not binary_path.is_file():
        raise RuntimeError(f"Invalid binary path: {binary_path}")

    output_path = Path(sys.argv[2])

    # Perform analysis
    try:
        analysis = analyze_binary(binary_path)
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # Write output JSON
    try:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2)
    except OSError as e:
        print(f"[ERROR] Cannot write output JSON: {e}")
        sys.exit(1)

    print(f"[+] Analysis complete. Output written to {output_path}")


if __name__ == "__main__":
    main()

