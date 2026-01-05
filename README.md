# x86_64 Linux-Based Kernel Agent Security Framework

## 1. Overview

This project implements a **hybrid system call security framework** combining **static and dynamic monitoring** with **layered enforcement**. **Seccomp-bpf** provides proactive, in-kernel restriction of system calls based on a learned whitelist, while **eBPF** performs dynamic, state-aware monitoring of system call execution at runtime.

Behavioural deviations are **detective only**, whereas **enforcement is strictly count-based**. When a system call exceeds its learned execution count, the monitoring daemon reactively terminates the target process using **SIGKILL**.

---

## 2. Key Features

* Hybrid syscall monitoring combining static and dynamic analysis
* Proactive, in-kernel syscall restriction using seccomp-bpf
* Dynamic, state-aware syscall observation using eBPF tracepoints
* Exact syscall transitions, execution count profiling during learning phase
* Runtime syscall count comparison against learned baseline
* Detective-only behavioural deviation monitoring
* Reactive enforcement triggered strictly by count violations
* Immediate process termination via SIGKILL on policy breach
* Clear separation of monitoring and enforcement responsibilities

---

## 3. System Architecture

---

## 4. Project Structure

```text
project_root/
├── Policy/
│   ├── policy_parser.c
│   ├── policy_parser.h
│   ├── policy-daemon.c
│   ├── ebpf_policy.bpf.c
│   ├── ebpf_helper.h
│   ├── seccomp_launcher.c
│   ├── seccomp_launcher.h
│   └── sandbox-run.c
│
├── static_tracer/
│   ├── main.py
│   ├── ldd.py
│   ├── syscall_finder.py
│   └── syscalls_x86_64_from_tbl.csv
│
├── Dynamic_Tracer/
│   ├── dynamic_tracer.bpf.c
│   └── dynamic_tracer.c
│
├── build/
│   ├── dynamic_tracer
│   ├── policy-daemon
│   └── sandbox-run
│ 
├── exploit/
│   ├── key_penetration.c
│   ├── sful_penetration.c
│   └── Makefile
│
├── web/
│   ├── templates
│   │   ├── index.html
│   │   ├── job_metrics.html
│   │   ├── metrics.html
│   │   └── policies.html
│   └── app.py
│
├── merge_all_run.py
├── merge_json.py
├── myagent-reg.sh
├── Makefile
├── README.md
└── requirements.txt
```

---

## 5. Technologies Used

* **Programming Languages:** C, Python
* **Kernel Technology:** eBPF
* **Security Mechanism:** seccomp-bpf
* **Libraries:** libbpf, libelf, jansson
* **Platform:** Linux_AMD64

---

## 6. Prerequisites

* Linux kernel with eBPF support
* clang / llvm
* gcc and make
* libbpf
* bpftool

---

## 7. Build Instructions

```bash
make
```
Install:

```bash
make install
```
Optional cleanup:

```bash
make clean
```

The compiled binaries are placed in the `build/` directory.

---

## 8. Usage

### 8.1 Learning / Recording Phase

1. Install required python libraries.

```bash
pip install -r requirements.txt
```
2. Run the pipeline from script

```bash
sudo ./myagent-reg.sh
```
3. OR: Run by Web Interface

```bash
python3 app.py
```
<img width="1318" height="751" alt="image" src="https://github.com/user-attachments/assets/94e628c7-2278-4d0a-9c6e-d9a6720bd104" />

   * Allowed syscalls with counts
   * Entry syscalls
   * Syscall Transitioins with counts

<img width="1249" height="845" alt="image" src="https://github.com/user-attachments/assets/63c6a574-3a12-4451-a103-90f1853ec5fb" />


This policy represents the **baseline behaviour** of the application.

---

### 8.2 Enforcement Phase

1. Launch the policy daemon.
```bash
sudo systemctl start policy.service
```

2. Enforce the layered Sandbox
```bash
./sandbox-run <policy-path> <run application>
```

If:

* A system call not in the whitelist is executed → blocked by seccomp
* A system call exceeds its recorded execution count → process is terminated
* A system call not in the whitelist transition is executed → warning 

---

## 9. Limitations

* Enforcement is AMD64 architecuture specific
* To avoid false positives, mulitiple learning is necessary.
* Requires kernel support for eBPF and seccomp.
* Operational cost for Dynamic and Initial overhead for Static

---

## 10. Author

**Hsu Shun Lae**
MSc Cybersecurity
Dublin Business School

---


