import sys
from pathlib import Path
import re

import capstone
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


MAX_BACKTRACK = 200
MAX_TEXT_SECTION_SIZE = 16 * 1024 * 1024  # 16 MB

# Disassemble the .text section of an x86/x86_64 ELF binary.
def elf_scanning(path):

    path = Path(path)

    try:
        with path.open("rb") as f:
            try:
                elf = ELFFile(f)
            except ELFError as e:
                raise RuntimeError(f"[ERROR] Not a valid ELF file: {path} ({e})") from e

            text_section = elf.get_section_by_name(".text")
            if text_section is None:
                raise RuntimeError(f"[ERROR] No .text section found in: {path}")

            size = text_section.data_size
            if size == 0:
                raise RuntimeError(f"[ERROR] .text section is empty in: {path}")
            if size > MAX_TEXT_SECTION_SIZE:
                raise RuntimeError(f"[ERROR] .text section too large ({size} bytes > {MAX_TEXT_SECTION_SIZE}) in: {path}")

            raw_bytes = text_section.data()
            base_addr = text_section["sh_addr"]
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True
            md.skipdata = True

            return list(md.disasm(raw_bytes, base_addr))

    except OSError as e:
        raise RuntimeError(f"[ERROR] OS error while reading {path}: {e}") from e


def normalize_register(name):
    match = re.match("[e|r]*([a-d])[x|l]", name)
    if match:
        return "r%sx" % match[1]
    match = re.match("[e|r]*([s|d])il?", name)
    if match:
        return "r%si" % match[1]
    match = re.match("[e|r]*([s|b])pl?", name)
    if match:
        return "r%sp" % match[1]
    match = re.match("r([0-9]+)[d|w|b]?", name)
    if match:
        return "r%s" % match[1]
    return name


def resolve_immediate(reg_state, reg_name):
    if reg_name in reg_state:
        entry = reg_state[reg_name]
        if entry["type"] == "value":
            return {"type": "value", "value": entry["value"]}
        return resolve_immediate(reg_state, entry["value"])
    return {"type": "register", "value": reg_name}


# Locate syscall instructions.
def find_syscall_sites(instructions):

    sites = []

    for idx, insn in enumerate(instructions):
        if insn is None:
            continue

        try:
            mnemonic = (insn.mnemonic or "").strip().lower()
        except AttributeError:
            continue

        if mnemonic == "syscall":
            addr = getattr(insn, "address", None)
            if isinstance(addr, int):
                sites.append((idx, addr))

    return sites


def find_syscall_number(instructions, syscall_index, max_backtrack=MAX_BACKTRACK):

    if not isinstance(instructions, (list, tuple)) or not instructions:
        return -1
    if not isinstance(syscall_index, int) or syscall_index < 0 or syscall_index >= len(instructions):
        return -1

    reg_state = {}

    for step in range(max_backtrack):
        pos = syscall_index - step
        if pos < 0:
            break

        insn = instructions[pos]
        if insn is None:
            continue

        try:
            mnemonic = (insn.mnemonic or "").lower()
        except AttributeError:
            continue

        try:
            _, regs_write = insn.regs_access()
        except Exception:
            continue

        if not regs_write:
            rax = resolve_immediate(reg_state, "rax")
            if isinstance(rax, dict) and rax.get("type") == "value":
                try:
                    return int(rax["value"])
                except (TypeError, ValueError):
                    pass
            continue

        if "mov" in mnemonic or "xor" in mnemonic:
            try:
                operands = insn.operands
            except AttributeError:
                operands = []

            if len(operands) != 2:
                continue

            dst_op = operands[0]
            src_op = operands[1]

            if dst_op.type != capstone.x86.X86_OP_REG:
                continue

            try:
                dst_name = normalize_register(insn.reg_name(dst_op.value.reg))
            except Exception:
                continue

            value_entry = {"type": "value", "value": 0}

            if src_op.type == capstone.x86.X86_OP_REG and "mov" in mnemonic:
                try:
                    src_name = normalize_register(insn.reg_name(src_op.value.reg))
                except Exception:
                    continue
                value_entry = resolve_immediate(reg_state, src_name)
            elif src_op.type == capstone.x86.X86_OP_IMM:
                value_entry = {"type": "value", "value": src_op.value.imm}

            if dst_name not in reg_state:
                reg_state[dst_name] = value_entry

        rax = resolve_immediate(reg_state, "rax")
        if isinstance(rax, dict) and rax.get("type") == "value":
            try:
                return int(rax["value"])
            except (TypeError, ValueError):
                continue

    return -1


def collect_syscalls(file):

    instructions = elf_scanning(file)
    syscall_sites = find_syscall_sites(instructions)

    results = []  

    for idx, addr in syscall_sites:
        nr = find_syscall_number(instructions, idx)
        if nr != -1:
            results.append((addr, nr))
        else:
            print(f"[ERROR] could not get syscall number @ {hex(int(addr))}")
            print("--------")

    return results
    

