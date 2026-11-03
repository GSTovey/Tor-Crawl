#!/usr/bin/env python3
"""Supervisor for Tor_over_Proxy / Traffic_Pairs via the user's obfs4 bridges.

Four jobs: top-anytls, pairs-anytls, top-hysteria2, pairs-hysteria2.
Writes STATUS_BRIDGE.md; the main finalize.py produces the combined manifest.
"""
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
STATUS_FILE = OUT / "STATUS_BRIDGE.md"
RUN_JOB = HERE / "run_job.py"
RUNTIME = HERE / "runtime"
SITE_LIST = ROOT / "docker" / "configs" / "top1000.txt"
TORRC = HERE / "torrc_bridges.template"
TARGET = 5000
MAX_PER_SITE = 10
MAX_PARALLEL = 4
MAX_RETRIES = 2
RUN_HOURS = 72
DISK_MIN_GB = 50

JOBS = [
    {"job": "top-anytls", "mode": "top", "protocol": "anytls", "base": "Tor_over_Proxy/anytls", "name": "rc-top-anytls"},
    {"job": "pairs-anytls", "mode": "pairs", "protocol": "anytls", "base": "Traffic_Pairs/anytls", "name": "rc-pairs-anytls"},
    {"job": "top-hysteria2", "mode": "top", "protocol": "hysteria2", "base": "Tor_over_Proxy/hysteria2", "name": "rc-top-hysteria2"},
    {"job": "pairs-hysteria2", "mode": "pairs", "protocol": "hysteria2", "base": "Traffic_Pairs/hysteria2", "name": "rc-pairs-hysteria2"},
]


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [bridge-supervisor] {msg}"
    print(line, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "supervisor_bridge.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def docker(*args: str, timeout: int | None = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


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


def progress_name(job: str) -> str:
    if job.startswith("top-"):
        return f"top__{job[4:]}.json"
    if job.startswith("pairs-"):
        return f"pairs__{job[6:]}.json"
    return f"{job}.json"


def read_progress(job: str) -> dict:
    p = PROGRESS / progress_name(job)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def launch(job: dict) -> bool:
    cmd = [
        sys.executable, str(RUN_JOB),
        "--job", job["job"],
        "--mode", job["mode"],
        "--protocol", job["protocol"],
        "--base-subdir", job["base"],
        "--target", str(TARGET),
        "--max-per-site", str(MAX_PER_SITE),
        "--site-list", str(SITE_LIST),
        "--output", str(OUT),
        "--runtime", str(RUNTIME),
        "--name", job["name"],
        "--request-timeout", "45",
        "--run-hours", str(RUN_HOURS),
        "--torrc", str(TORRC),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        log(f"launch {job['job']} failed: {p.stderr.strip()[:400]}")
        return False
    log(f"launched {job['job']} ({job['name']})")
    return True


def write_status(running: dict, done: set, failed: dict) -> None:
    lines = [
        "# Tor-over-Proxy / Traffic-Pairs status",
        "",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%S%z')}",
        "",
        "| Job | Status | Captured | Target | Attempts | Sites | Node | Last error |",
        "|---|---|---:|---:|---:|---:|---|---|",
    ]
    for job in JOBS:
        jid = job["job"]
        status = "done" if jid in done else (f"failed({failed[jid]})" if jid in failed else ("running" if jid in running else "pending"))
        pr = read_progress(jid)
        lines.append(
            f"| {jid} | {status} | {pr.get('captured', 0)} | {pr.get('target', TARGET)} | "
            f"{pr.get('attempts', 0)} | {pr.get('sites_done', 0)}/{pr.get('sites_total', '?')} | "
            f"{pr.get('current_node', '')} | {str(pr.get('last_error', ''))[:100]} |"
        )
    lines += ["", f"STOP file: {STOP_FILE}", "", "Bridge: torrc_bridges.template (user-provided obfs4)", ""]
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
            log(f"adopted already-finished job {jid}")

    log(f"jobs: {[j['job'] for j in JOBS]}")
    while pending or running:
        if STOP_FILE.exists():
            log("STOP file detected; stopping running bridge jobs")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        if RUN_HOURS > 0 and time.time() - started > RUN_HOURS * 3600:
            log("bridge supervisor 72h cap reached; stopping")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        try:
            free_gb = shutil.disk_usage(str(OUT)).free / (1024 ** 3)
        except Exception:
            free_gb = 10 ** 9
        if free_gb < DISK_MIN_GB:
            log(f"disk low ({free_gb:.1f} GB); stopping bridge jobs")
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
                (LOG_DIR / f"{jid}.container.log").write_text(
                    logs.stdout or "", encoding="utf-8", errors="replace"
                )
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
    log("bridge supervisor finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
