#!/usr/bin/env python3
"""Supervisor for self-hosted Pure Trojan/SS jobs (Xray server + hy2 upstream)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "2026-10-28_Recapture"
META = OUT / "_meta"
PROGRESS = META / "progress"
LOG_DIR = META / "logs"
STOP_FILE = META / "STOP"
STATUS_FILE = OUT / "STATUS_SELFHOST.md"
RUN_JOB = HERE / "run_job.py"
RUNTIME = HERE / "runtime"
SITE_LIST = OUT / "_preflight" / "reachable_hysteria2.txt"
NETWORK = "recapture-servers"
TARGET = 5000
MAX_PER_SITE = 8
MAX_PARALLEL = 2
MAX_RETRIES = 2
RUN_HOURS = 72
DISK_MIN_GB = 50

JOBS = [
    {"job": "pure-trojan-local", "mode": "pure", "protocol": "trojan", "base": "Pure_Proxy/trojan", "name": "rc-pure-trojan-local", "progress": "pure__trojan.json"},
    {"job": "pure-ss-local", "mode": "pure", "protocol": "ss", "base": "Pure_Proxy/ss", "name": "rc-pure-ss-local", "progress": "pure__ss.json"},
]


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [selfhost-supervisor] {msg}"
    print(line, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "supervisor_selfhost.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def docker(*args: str, timeout: int | None = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def container_state(name: str) -> tuple[str, int | None]:
    p = docker("inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name)
    if p.returncode != 0:
        return "missing", None
    parts = p.stdout.strip().split()
    status = parts[0] if parts else "unknown"
    try:
        code = int(parts[1]) if len(parts) > 1 else None
    except ValueError:
        code = None
    return status, code


def read_progress(job: dict) -> dict:
    try:
        return json.loads((PROGRESS / job["progress"]).read_text(encoding="utf-8"))
    except Exception:
        return {}


def launch(job: dict) -> bool:
    cmd = [
        sys.executable, str(RUN_JOB),
        "--job", job["job"], "--mode", job["mode"], "--protocol", job["protocol"],
        "--base-subdir", job["base"], "--target", str(TARGET),
        "--max-per-site", str(MAX_PER_SITE), "--site-list", str(SITE_LIST),
        "--output", str(OUT), "--runtime", str(RUNTIME), "--name", job["name"],
        "--request-timeout", "15", "--run-hours", str(RUN_HOURS), "--network", NETWORK,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        log(f"launch {job['job']} failed: {p.stderr.strip()[:400]}")
        return False
    log(f"launched {job['job']} ({job['name']})")
    return True


def write_status(running: dict, done: set, failed: dict) -> None:
    lines = [
        "# Self-hosted Pure Trojan/SS status",
        "",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%S%z')}",
        "",
        "Topology: capture -> mihomo (Trojan/SS) -> local Xray server -> Hysteria2 upstream (hy0030) -> target",
        "",
        "| Job | Status | Captured | Target | Attempts | Sites | Last error |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for job in JOBS:
        jid = job["job"]
        status = "done" if jid in done else (f"failed({failed[jid]})" if jid in failed else ("running" if jid in running else "pending"))
        pr = read_progress(job)
        lines.append(
            f"| {jid} | {status} | {pr.get('captured', 0)} | {pr.get('target', TARGET)} | "
            f"{pr.get('attempts', 0)} | {pr.get('sites_done', 0)}/{pr.get('sites_total', '?')} | "
            f"{str(pr.get('last_error', ''))[:100]} |"
        )
    lines += ["", f"STOP file: {STOP_FILE}", ""]
    STATUS_FILE.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    META.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PROGRESS.mkdir(parents=True, exist_ok=True)
    jobs = {j["job"]: j for j in JOBS}
    pending = [j["job"] for j in JOBS]
    running: dict[str, dict] = {}
    done: set[str] = set()
    failed: dict[str, int] = {}
    retries = {j: 0 for j in jobs}
    started = time.time()

    for jid in list(pending):
        status, code = container_state(jobs[jid]["name"])
        if status == "running":
            running[jid] = jobs[jid]
            pending.remove(jid)
            log(f"adopted running container {jobs[jid]['name']}")
        elif status in ("exited", "dead") and code == 0:
            done.add(jid)
            pending.remove(jid)

    log(f"jobs: {[j['job'] for j in JOBS]}")
    while pending or running:
        if STOP_FILE.exists():
            log("STOP file detected; stopping self-host jobs")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        if RUN_HOURS > 0 and time.time() - started > RUN_HOURS * 3600:
            log("selfhost 72h cap reached")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        try:
            free_gb = shutil.disk_usage(str(OUT)).free / (1024 ** 3)
        except Exception:
            free_gb = 10 ** 9
        if free_gb < DISK_MIN_GB:
            log(f"disk low ({free_gb:.1f} GB)")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break

        while pending and len(running) < MAX_PARALLEL:
            jid = pending.pop(0)
            if launch(jobs[jid]):
                running[jid] = jobs[jid]
            else:
                retries[jid] += 1
                if retries[jid] <= MAX_RETRIES:
                    pending.append(jid)
                else:
                    failed[jid] = retries[jid]

        for jid, job in list(running.items()):
            status, code = container_state(job["name"])
            if status in ("exited", "dead", "created", "missing"):
                logs = docker("logs", "--tail", "5000", job["name"])
                (LOG_DIR / f"{jid}.container.log").write_text(logs.stdout or "", encoding="utf-8", errors="replace")
                if code == 0:
                    log(f"{jid} finished successfully")
                    done.add(jid)
                    running.pop(jid, None)
                else:
                    retries[jid] += 1
                    log(f"{jid} exited code={code}, retry {retries[jid]}")
                    if retries[jid] <= MAX_RETRIES:
                        if launch(jobs[jid]):
                            pass
                        else:
                            pending.append(jid)
                            running.pop(jid, None)
                    else:
                        failed[jid] = retries[jid]
                        running.pop(jid, None)

        write_status(running, done, failed)
        time.sleep(30)

    write_status(running, done, failed)
    log("selfhost supervisor finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
