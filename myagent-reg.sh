#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ---------- Config ----------
STATE_DIR="/home/hsu/project_final"
APPS_DIR="${STATE_DIR}/apps"
SCAN_DIR="${STATE_DIR}/scan"
LOGFILE="/var/log/myagent.log"
TAG="myagent"

PYTHON="/usr/bin/python3"
STATIC_TRACER="${STATE_DIR}/static_tracer/main.py"
DYNAMIC_TRACER="${STATE_DIR}/build/dynamic_tracer"


MERGER_BOOTSTRAP="${STATE_DIR}/merge_json.py"
MERGER_CUMULATIVE="${STATE_DIR}/merge_all_run.py"

JOB_ID="${JOB_ID:-}"
JOB_DIR="${STATE_DIR}/run/jobs"

# ---------- Status ----------
mark_status() {
  [[ -z "$JOB_ID" ]] && return 0
  echo "$1" > "${JOB_DIR}/${JOB_ID}.status"
}

trap 'mark_status "failed"' ERR

mkdir -p "$APPS_DIR" "$SCAN_DIR" "$JOB_DIR"


log() {
  logger -t "$TAG" -- "$*"
  printf '%s %s\n' "$(date -Is)" "$*" >>"$LOGFILE"
}

valid_exec() { [[ -f "$1" && -x "$1" && ! -L "$1" ]]; }
app_name() { basename "$1" | tr -c 'A-Za-z0-9._-' '_'; }

sign_json() {
  local f="$1"
  chmod 0444 "$f"
  sha256sum "$f" | awk '{print $1}' > "${f}.sig"
  chmod 0440 "${f}.sig"
}

cmd_add() {
  local real
  real="$(readlink -f "$1")"
  valid_exec "$real" || { echo "invalid executable"; exit 1; }

  local name dir scan
  name="$(app_name "$real")"
  dir="${APPS_DIR}/${name}"
  scan="${SCAN_DIR}/${name}"

  install -d -m 0755 "$dir" "$scan"

  jq -n \
    --arg name "$name" \
    --arg path "$real" \
    '{name:$name, path:$path}' \
    >"$dir/metadata.json"

  chmod 0640 "$dir/metadata.json"
  log "[add] $name $real"
  echo "[+] Registered: $name"
}

# ---------- SCAN ONE ----------
scan_one() {
  mark_status "running"

  local name="$1"; shift
  local args=("$@")

  local meta="${APPS_DIR}/${name}/metadata.json"
  [[ -f "$meta" ]] || { echo "not registered: $name"; exit 1; }

  local path
  path="$(jq -r '.path' "$meta")"

  local s d out tmp
  s="${SCAN_DIR}/${name}/${name}static.json"
  d="${SCAN_DIR}/${name}/${name}dynamic.json"
  out="${SCAN_DIR}/${name}/${name}policy.json"
  tmp="${out}.tmp"

  # ---- STATIC ----
  "$PYTHON" "$STATIC_TRACER" "$path" "$s"
  sign_json "$s"
  log "[static] $name"

  # ---- DYNAMIC ----
  "$DYNAMIC_TRACER" \
    --out "$d" \
    "$path" "${args[@]}"
  sign_json "$d"
  log "[dynamic] $name"

  # ---- MERGE ----
  if [[ -f "$out" ]]; then
    # Existing policy → cumulative merge
    "$PYTHON" "$MERGER_CUMULATIVE" \
      --policy-a "$out" \
      --policy-b "$d" \
      --out "$tmp"
  else
    # First run → bootstrap
    "$PYTHON" "$MERGER_BOOTSTRAP" \
      --policy-a "$s" \
      --policy-b "$d" \
      --out "$tmp"
  fi

  mv "$tmp" "$out"
  sign_json "$out"
  log "[merge] $name"

  mark_status "done"
  echo "[+] Policy ready: $out"
}

cmd_scan() {
  if [[ "${1:-}" == "--all" ]]; then
    shift
    for m in "$APPS_DIR"/*/metadata.json; do
      scan_one "$(basename "$(dirname "$m")")" "$@"
    done
  elif [[ $# -ge 1 ]]; then
    local name="$1"; shift
    scan_one "$name" "$@"
  else
    echo "usage: scan <name> [args...] | scan --all [args...]" >&2
    exit 2
  fi
}

cmd_list() {
  ls "$APPS_DIR" 2>/dev/null || echo "No apps registered."
}

cmd_remove() {
  rm -rf "${APPS_DIR}/$1"
  rm -rf "${SCAN_DIR}/$1"
  log "[remove] $1"
  echo "[-] Removed: $1"
}

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

case "${1:-}" in
  add)    shift; cmd_add "$@" ;;
  scan)   shift; cmd_scan "$@" ;;
  list)   cmd_list ;;
  remove) shift; cmd_remove "$@" ;;
  *) echo "usage: $0 add|scan|list|remove"; exit 1 ;;
esac

