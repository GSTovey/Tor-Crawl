#!/usr/bin/env python3
"""Pairs-only supervisor: maximize Traffic_Pairs over a 72 h extended window.

ToP jobs are stopped for this phase.  Pairs jobs use a 5000-domain list,
30 s request timeout and 2 retries to increase site throughput.
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
STATUS_FILE = OUT / "STATUS_PAIRS_ONLY.md"
RUN_JOB = HERE / "run_job.py"
RUNTIME = HERE / "runtime"
SITE_LIST = ROOT / "docker" / "recapture" / "top5000.txt"
TORRC = HERE / "torrc_bridges.template"
TARGET = 5000
MAX_PER_SITE = 10
REQUEST_TIMEOUT = 30
MAX_RETRIES = 2
RUN_HOURS = 72
MAX_PARALLEL = 6
DISK_MIN_GB = 50
NET_LOCAL = "recapture-servers"

JOBS = [
    {"job": "pairs-anytls", "mode": "pairs", "protocol": "anytls",
     "base": "Traffic_Pairs/anytls", "name": "rc-pairs-anytls",
     "runtime": "pairs-anytls", "progress": "pairs__anytls.json", "network": ""},
    {"job": "pairs-hysteria2", "mode": "pairs", "protocol": "hysteria2",
     "base": "Traffic_Pairs/hysteria2", "name": "rc-pairs-hysteria2",
     "runtime": "pairs-hysteria2", "progress": "pairs__hysteria2.json", "network": ""},
    {"job": "pairs-vless-local", "mode": "pairs", "protocol": "vless",
     "base": "Traffic_Pairs/vless", "name": "rc-pairs-vless-local",
     "runtime": "pairs-vless-local", "progress": "pairs__vless.json", "network": NET_LOCAL},
    {"job": "pairs-trojan-local", "mode": "pairs", "protocol": "trojan",
     "base": "Traffic_Pairs/trojan", "name": "rc-pairs-trojan-local",
     "runtime": "pairs-trojan-local", "progress": "pairs__trojan.json", "network": NET_LOCAL},
    {"job": "pairs-ss-local", "mode": "pairs", "protocol": "ss",
     "base": "Traffic_Pairs/ss", "name": "rc-pairs-ss-local",
     "runtime": "pairs-ss-local", "progress": "pairs__ss.json", "network": NET_LOCAL},
    {"job": "pairs-vmess-local", "mode": "pairs", "protocol": "vmess",
     "base": "Traffic_Pairs/vmess", "name": "rc-pairs-vmess-local",
     "runtime": "pairs-vmess-local", "progress": "pairs__vmess.json", "network": NET_LOCAL},
]


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [pairs-only] {msg}"
    print(line, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "supervisor_pairs_only.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def docker(*args: str, timeout: int | None = 60):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout
    )


def state(name: str):
    p = docker("inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name)
    if p.returncode != 0:
        return "missing", None
    parts = p.stdout.strip().split()
    st = parts[0] if parts else "unknown"
    try:
        code = int(parts[1]) if len(parts) > 1 else None
    except ValueError:
        code = None
    return st, code


def prog(job: dict) -> dict:
    try:
        return json.loads((PROGRESS / job["progress"]).read_text(encoding="utf-8"))
    except Exception:
        return {}


def launch(job: dict) -> bool:
    cmd = [
        sys.executable, str(RUN_JOB),
        "--job", job["job"], "--mode", "pairs", "--protocol", job["protocol"],
        "--base-subdir", job["base"], "--target", str(TARGET),
        "--max-per-site", str(MAX_PER_SITE), "--site-list", str(SITE_LIST),
        "--output", str(OUT), "--runtime", str(RUNTIME), "--name", job["name"],
        "--request-timeout", str(REQUEST_TIMEOUT), "--max-retries", str(MAX_RETRIES),
        "--run-hours", str(RUN_HOURS), "--torrc", str(TORRC),
    ]
    if job["network"]:
        cmd += ["--network", job["network"]]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        log(f"launch {job['job']} failed: {p.stderr.strip()[:400]}")
        return False
    log(f"launched {job['job']} ({job['name']})")
    return True


def write_status(running: dict, done: set, failed: dict) -> None:
    lines = [
        "# Pairs-only phase (ToP paused)",
        "",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%S%z')}",
        "",
        "ToP jobs were stopped to give Tor/bridge/upstream capacity to Pairs.",
        f"Site list: Umbrella top 5000; timeout {REQUEST_TIMEOUT}s; retries {MAX_RETRIES}",
        "",
        "| Job | Status | Captured | Target | Sites | Last error |",
        "|---|---|---:|---:|---:|---|",
    ]
    for job in JOBS:
        jid = job["job"]
        st = "done" if jid in done else f"failed({failed[jid]})" if jid in failed else "running" if jid in running else "pending"
        pr = prog(job)
        lines.append(
            f"| {jid} | {st} | {pr.get('captured', 0)} | {pr.get('target', TARGET)} | "
            f"{pr.get('sites_done', 0)}/{pr.get('sites_total', '?')} | "
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
        st, code = state(jobs[jid]["name"])
        if st == "running":
            running[jid] = jobs[jid]
            pending.remove(jid)
            log(f"adopted {jobs[jid]['name']}")
        elif st in ("exited", "dead") and code == 0:
            done.add(jid)
            pending.remove(jid)

    log(f"jobs: {[j['job'] for j in JOBS]}")
    while pending or running:
        if STOP_FILE.exists():
            log("STOP detected")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        if time.time() - started > RUN_HOURS * 3600:
            log("72h pairs-only cap reached")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break
        try:
            free = shutil.disk_usage(str(OUT)).free / (1024 ** 3)
        except Exception:
            free = 10 ** 9
        if free < DISK_MIN_GB:
            log(f"disk low {free:.1f} GB")
            for job in running.values():
                docker("stop", job["name"], timeout=60)
            break

        while pending and len(running) < MAX_PARALLEL:
            jid = pending.pop(0)
            if launch(jobs[jid]):
                running[jid] = jobs[jid]
            else:
                retries[jid] += 1
                if retries[jid] <= 2:
                    pending.append(jid)
                else:
                    failed[jid] = retries[jid]

        for jid, job in list(running.items()):
            st, code = state(job["name"])
            if st in ("exited", "dead", "created", "missing"):
                logs = docker("logs", "--tail", "5000", job["name"])
                (LOG_DIR / f"{jid}.container.log").write_text(
                    logs.stdout or "", encoding="utf-8", errors="replace"
                )
                if code == 0:
                    log(f"{jid} done")
                    done.add(jid)
                    running.pop(jid, None)
                else:
                    retries[jid] += 1
                    log(f"{jid} exited {code}, retry {retries[jid]}")
                    if retries[jid] <= 2:
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
    log("pairs-only supervisor finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
