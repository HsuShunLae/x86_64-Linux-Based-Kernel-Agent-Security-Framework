from flask import Flask, render_template, request, jsonify
import subprocess
import uuid
import os
import json
from pathlib import Path
import signal

import threading
import time
import psutil


SCRIPT = "/home/hsu/project_final/myagent-reg.sh"
BASE = "/home/hsu/project_final"
JOB_DIR = f"{BASE}/run/jobs"
SCAN_DIR = f"{BASE}/scan"
APPS_DIR = f"{BASE}/apps"

Path(JOB_DIR).mkdir(parents=True, exist_ok=True)

app = Flask(__name__)


def _safe_name(s: str) -> bool:
    if not s:
        return False
    if "/" in s or ".." in s:
        return False
    return True

def _job_files(job_id: str):
    return (
        f"{JOB_DIR}/{job_id}.status",
        f"{JOB_DIR}/{job_id}.meta",
        f"{JOB_DIR}/{job_id}.out",
        f"{JOB_DIR}/{job_id}.err",
    )

def _set_status(job_id: str, status: str):
    status_file, _, _, _ = _job_files(job_id)
    with open(status_file, "w") as f:
        f.write(status)

def _write_job_meta(job_id: str, meta: dict):
    _, meta_file, _, _ = _job_files(job_id)
    with open(meta_file, "w") as f:
        json.dump(meta, f)

def _read_job_meta(job_id: str):
    _, meta_file, _, _ = _job_files(job_id)
    if not os.path.exists(meta_file):
        return None
    with open(meta_file) as f:
        return json.load(f)

def _read_status(job_id: str) -> str:
    status_file, _, _, _ = _job_files(job_id)
    if not os.path.exists(status_file):
        return "unknown"
    return open(status_file).read().strip() or "unknown"

def _tail(path: str, n_lines: int = 200) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        data = f.read()
    lines = data.splitlines()[-n_lines:]
    try:
        return b"\n".join(lines).decode("utf-8", errors="replace")
    except Exception:
        return ""

def _load_policy(app_name: str):
    policy_path = f"{SCAN_DIR}/{app_name}/{app_name}policy.json"
    if not os.path.exists(policy_path):
        return None
    with open(policy_path) as f:
        return json.load(f)
        
def sample_job_resources(job_id: str, stop_event: threading.Event, root_pid: int):
    points = []
    start_ns = time.perf_counter_ns()

    try:
        root = psutil.Process(root_pid)
        root.cpu_percent(interval=None)  
    except psutil.NoSuchProcess:
        root = None

    disk0 = psutil.disk_io_counters()

    while not stop_event.is_set():
        t_ns = time.perf_counter_ns() - start_ns
        t_ms = round(t_ns / 1_000_000, 3)

        rss_bytes = 0
        cpu_pct = 0.0

        if root:
            procs = [root]
            try:
                procs += root.children(recursive=True)
            except Exception:
                pass

            for p in procs:
                try:
                    rss_bytes += p.memory_info().rss
                except Exception:
                    pass

            try:
                cpu_pct = root.cpu_percent(interval=None)
            except Exception:
                pass

        disk_now = psutil.disk_io_counters()
        disk_mb = round(
            ((disk_now.read_bytes - disk0.read_bytes) +
             (disk_now.write_bytes - disk0.write_bytes)) / (1024 * 1024),
            3
        )

        points.append({
            "t_ms": t_ms,
            "cpu_job": round(cpu_pct, 2),
            "ram_job_mb": round(rss_bytes / (1024 * 1024), 3),
            "disk_mb": disk_mb
        })

        time.sleep(0.5) 

    with open(f"{JOB_DIR}/{job_id}.metrics.json", "w") as f:
        json.dump({
            "job_id": job_id,
            "points": points
        }, f, indent=2)


@app.route("/")
def index():
    return render_template("index.html")



@app.route("/api/list", methods=["GET"])
def api_list():
   
    r = subprocess.run(["sudo", SCRIPT, "list"], capture_output=True, text=True)
    apps = [a.strip() for a in r.stdout.splitlines() if a.strip()]
    return jsonify({"apps": apps})

@app.route("/api/add", methods=["POST"])
def api_add():
    path = request.form.get("path", "").strip()
    if not path:
        return jsonify({"ok": False, "error": "missing path"}), 400

    r = subprocess.run(["sudo", SCRIPT, "add", path], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr.strip() or r.stdout.strip() or "add failed")}), 500

    
    return jsonify({"ok": True, "output": r.stdout.strip()})

@app.route("/api/remove", methods=["POST"])
def api_remove():
    name = request.form.get("name", "").strip()
    if not _safe_name(name):
        return jsonify({"ok": False, "error": "invalid name"}), 400

    r = subprocess.run(["sudo", SCRIPT, "remove", name], capture_output=True, text=True)
    if r.returncode != 0:
        return jsonify({"ok": False, "error": (r.stderr.strip() or r.stdout.strip() or "remove failed")}), 500

    return jsonify({"ok": True, "output": r.stdout.strip()})
    


@app.route("/api/scan", methods=["POST"])
def api_scan_one():
    name = request.form.get("name", "").strip()
    args = request.form.get("args", "").strip()

    if not _safe_name(name):
        return jsonify({"ok": False, "error": "invalid name"}), 400
    if not args:
        return jsonify({"ok": False, "error": "args required"}), 400

    job_id = uuid.uuid4().hex
    _, _, out_file, err_file = _job_files(job_id)

    _set_status(job_id, "queued")

    out = open(out_file, "w")
    err = open(err_file, "w")

    t0_ns = time.perf_counter_ns()

    cmd = ["sudo", SCRIPT, "scan", name] + args.split()


    proc = subprocess.Popen(
        cmd,
        stdout=out,
        stderr=err,
        close_fds=True,
        preexec_fn=os.setsid
    )

    _set_status(job_id, "running")

    _write_job_meta(job_id, {
        "mode": "one",
        "apps": [name],
        "args": args,
        "t0_ns": t0_ns,
        "pgid": os.getpgid(proc.pid)
    })

    stop_event = threading.Event()

    threading.Thread(
        target=sample_job_resources,
        args=(job_id, stop_event, proc.pid),
        daemon=True
    ).start()

    def wait_and_finalize():
        try:
            ret = proc.wait()
            _set_status(job_id, "done" if ret == 0 else "failed")
        finally:
            meta = _read_job_meta(job_id) or {}
            meta["t1_ns"] = time.perf_counter_ns()
            _write_job_meta(job_id, meta)
            stop_event.set()

    threading.Thread(target=wait_and_finalize, daemon=True).start()

    return jsonify({"ok": True, "job_id": job_id})

 


@app.route("/api/scan_all", methods=["POST"])
def api_scan_all():
    args = request.form.get("args", "").strip()
    if not args:
        return jsonify({"ok": False, "error": "args required"}), 400

    job_id = uuid.uuid4().hex
    _, _, out_file, err_file = _job_files(job_id)

    _set_status(job_id, "queued")

    apps = []
    if os.path.exists(APPS_DIR):
        apps = sorted(
            d for d in os.listdir(APPS_DIR)
            if os.path.isdir(os.path.join(APPS_DIR, d))
        )

    out = open(out_file, "w")
    err = open(err_file, "w")

    t0_ns = time.perf_counter_ns()

    cmd = ["sudo", SCRIPT, "scan", "--all"] + args.split()

    proc = subprocess.Popen(
        cmd,
        stdout=out,
        stderr=err,
        close_fds=True,
        preexec_fn=os.setsid
    )

    _set_status(job_id, "running")

    _write_job_meta(job_id, {
        "mode": "all",
        "apps": apps,
        "args": args,
        "t0_ns": t0_ns,
        "pgid": os.getpgid(proc.pid)
    })

    stop_event = threading.Event()

    threading.Thread(
        target=sample_job_resources,
        args=(job_id, stop_event, proc.pid),
        daemon=True
    ).start()

    def wait_and_finalize():
        try:
            ret = proc.wait()
            _set_status(job_id, "done" if ret == 0 else "failed")
        finally:
            meta = _read_job_meta(job_id) or {}
            meta["t1_ns"] = time.perf_counter_ns()
            _write_job_meta(job_id, meta)
            stop_event.set()

    threading.Thread(target=wait_and_finalize, daemon=True).start()

    return jsonify({"ok": True, "job_id": job_id, "apps": apps})


@app.route("/api/job/<job_id>", methods=["GET"])
def api_job(job_id):
    # status
    st = _read_status(job_id)
    meta = _read_job_meta(job_id) or {}
    _, _, out_file, err_file = _job_files(job_id)
    
    duration_ms = None
    if "t0_ns" in meta and "t1_ns" in meta:
        duration_ms = round((meta["t1_ns"] - meta["t0_ns"]) / 1_000_000, 3)

    results = {}
    if st == "done":
        for name in meta.get("apps", []):
            if _safe_name(name):
                pol = _load_policy(name)
                if pol is not None:
                    results[name] = pol

    return jsonify({
        "job_id": job_id,
        "status": st,
        "meta": meta,
        "duration_ms": duration_ms,
        "stdout_tail": _tail(out_file, 200),
        "stderr_tail": _tail(err_file, 200),
        "results": results
    })
    
@app.route("/policies")
def policies():
    return render_template("policies.html")

    
@app.route("/api/policies")
def api_policies():
    import csv

    SYSCALL_CSV = "/home/hsu/project_final/static_tracer/syscalls_x86_64_from_tbl.csv"

    
    syscall_map = {}
    with open(SYSCALL_CSV, newline="") as f:
        reader = csv.reader(f)   
        for row in reader:
            if len(row) < 2:
                continue
            try:
                syscall_map[int(row[0].strip())] = row[1].strip()
            except ValueError:
                continue

    results = {}

    for app in os.listdir(SCAN_DIR):
        policy_path = f"{SCAN_DIR}/{app}/{app}policy.json"
        if not os.path.exists(policy_path):
            continue

        with open(policy_path) as f:
            policy = json.load(f)

        allowed = policy.get("allowed_syscalls", [])
        entry = policy.get("entry_syscalls", [])
        transitions = policy.get("allowed_transitions", [])
        syscall_counts = policy.get("syscall_counts", [])
        transition_counts = policy.get("transition_counts", [])

        results[app] = {
            "summary": {
                "allowed_syscalls": len(allowed),
                "entry_syscalls": len(entry),
                "total_transitions": len(transition_counts)
            },
            "allowed_syscalls": [
                {"id": sc, "name": syscall_map.get(sc, "UNKNOWN")}
                for sc in allowed
            ],
            "entry_syscalls": [
                {"id": sc, "name": syscall_map.get(sc, "UNKNOWN")}
                for sc in entry
            ],
            "syscall_counts": [
                {
                    "id": sc,
                    "name": syscall_map.get(sc, "UNKNOWN"),
                    "count": cnt
                }
                for sc, cnt in syscall_counts
            ],
            "transition_counts": [
                {
                    "from": src,
                    "from_name": syscall_map.get(src, "UNKNOWN"),
                    "to": dst,
                    "to_name": syscall_map.get(dst, "UNKNOWN"),
                    "count": cnt
                }
                for src, dst, cnt in transition_counts
            ]
        }

    return jsonify(results)
    
    

        
@app.route("/job/<job_id>/metrics")
def job_metrics_page(job_id):
    return render_template("job_metrics.html", job_id=job_id)
    

@app.route("/api/job/<job_id>/metrics", methods=["GET"])
def api_job_metrics(job_id):
    path = f"{JOB_DIR}/{job_id}.metrics.json"
    if not os.path.exists(path):
        return jsonify({"job_id": job_id, "metrics": []}), 200

    with open(path) as f:
        payload = json.load(f)

    return jsonify({
        "job_id": job_id,
        "metrics": payload.get("points", [])
    })
    
@app.route("/api/metrics/all", methods=["GET"])
def api_metrics_all():
    jobs = []

    for f in os.listdir(JOB_DIR):
        if not f.endswith(".metrics.json"):
            continue

        job_id = f.replace(".metrics.json", "")
        meta = _read_job_meta(job_id) or {}

        try:
            with open(os.path.join(JOB_DIR, f)) as fp:
                payload = json.load(fp)
        except Exception:
            continue

        
        if isinstance(payload, list):
            points = payload
        elif isinstance(payload, dict):
            points = payload.get("points", [])
        else:
            points = []

        if not points:
            continue

       
        ram_vals = [p.get("ram_job_mb", 0) for p in points]
        peak_ram = round(max(ram_vals), 3)

       
        cpu_vals = [p.get("cpu_job", 0) for p in points if "cpu_job" in p]
        avg_cpu = round(sum(cpu_vals) / len(cpu_vals), 2) if cpu_vals else 0.0
        peak_cpu = round(max(cpu_vals), 2) if cpu_vals else 0.0

        
        disk_vals = [p.get("disk_mb", 0) for p in points]
        total_disk_mb = round(max(disk_vals), 3) if disk_vals else 0.0

        
        duration_ms = None
        if "t0_ns" in meta and "t1_ns" in meta:
            duration_ms = round((meta["t1_ns"] - meta["t0_ns"]) / 1_000_000, 3)

        jobs.append({
            "job_id": job_id,
            "apps": meta.get("apps", []),
            "duration_ms": duration_ms,
            "peak_ram_mb": peak_ram,
            "avg_cpu": avg_cpu,
            "peak_cpu": peak_cpu,
            "disk_mb": total_disk_mb
        })

    return jsonify(jobs)

    
@app.route("/metrics")
def metrics_page():
    return render_template("metrics.html")

@app.route("/api/job/<job_id>/stop", methods=["POST"])
def api_stop_job(job_id):
    status = _read_status(job_id)

    if status in ("done", "failed", "stopped"):
        return jsonify({
            "ok": False,
            "error": "job already finished"
        }), 400

    _set_status(job_id, "stopped")

    return jsonify({
        "ok": True,
        "job_id": job_id,
        "message": "job marked as stopped (execution continues)"
    })



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

