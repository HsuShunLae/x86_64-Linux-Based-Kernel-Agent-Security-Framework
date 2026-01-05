#!/usr/bin/env python3

# adapted from https://gitweb.gentoo.org/proj/elfix.git/tree/pocs/ldd/ldd.py
"""
Secure static ELF dependency resolver.
"""

from pathlib import Path
import re
import glob

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError
from elftools.elf.descriptions import describe_ei_class


class DependencyError(RuntimeError):
    pass


def _open_elf(path):
    try:
        f = path.open("rb")
        return ELFFile(f)
    except (OSError, ELFError) as e:
        raise DependencyError(f"[ERROR] Failed to read ELF file: {path}") from e


def _elf_class(elf):
    return describe_ei_class(elf.header["e_ident"]["EI_CLASS"])


def _parse_ld_so_conf(conf, paths):
    try:
        text = conf.read_text()
    except OSError:
        return

    text = re.sub(r"#.*", "", text)
    tokens = re.split(r"[\s,:]+", text)

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if not tok:
            continue
        if tok == "include" and i < len(tokens):
            for g in glob.glob(tokens[i]):
                _parse_ld_so_conf(Path(g), paths)
            i += 1
        else:
            p = Path(tok).resolve()
            if p.exists():
                paths.add(p)


def _system_library_paths():
    paths = set()
    _parse_ld_so_conf(Path("/etc/ld.so.conf"), paths)

    for p in ("/lib", "/lib64", "/usr/lib", "/usr/lib64"):
        rp = Path(p).resolve()
        if rp.exists():
            paths.add(rp)

    return paths


def _dynamic_info(elf):
    needed = []
    rpaths = []

    for sec in elf.iter_sections():
        if not isinstance(sec, DynamicSection):
            continue
        for tag in sec.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                needed.append(tag.needed)
            elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                rpaths.extend(tag.rpath.split(":"))

    return needed, rpaths


def _resolve_library(name, elf_class, search_paths):
    for base in sorted(search_paths):
        candidate = (base / name).resolve()
        if not candidate.exists():
            continue
        try:
            elf = _open_elf(candidate)
            if _elf_class(elf) == elf_class:
                return candidate
        except DependencyError:
            continue
    return None


def _resolve_recursive(binary, elf_class, base_paths, resolved, visited):
    if binary in visited:
        return
    visited.add(binary)

    try:
        elf = _open_elf(binary)
    except DependencyError:
        return

    needed, rpaths = _dynamic_info(elf)

    local_paths = set(base_paths)
    for rp in rpaths:
        p = (binary.parent / rp).resolve()
        if p.exists():
            local_paths.add(p)

    for lib in needed:
        if lib in resolved:
            continue
        resolved_path = _resolve_library(lib, elf_class, local_paths)
        if resolved_path:
            resolved[lib] = resolved_path
            _resolve_recursive(resolved_path, elf_class, base_paths, resolved, visited)


def get_dependencies(binary):
    bin_path = Path(binary).resolve()
    if not bin_path.is_file():
        raise DependencyError(f"[ERROR] Binary does not exist: {binary}")

    elf = _open_elf(bin_path)
    elf_class = _elf_class(elf)

    base_paths = _system_library_paths()
    resolved = {}
    visited = set()

    _resolve_recursive(bin_path, elf_class, base_paths, resolved, visited)

    return [str(p) for p in resolved.values()]


if __name__ == "__main__":
    import sys
    try:
        for d in get_dependencies(sys.argv[1]):
            print(d)
    except DependencyError as e:
        sys.exit(f"[ldd error] {e}")




