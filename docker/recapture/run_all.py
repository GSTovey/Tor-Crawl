#!/usr/bin/env python3
"""Unattended supervisor for the 2026-10-28 recapture.

Runs Pure_Proxy (available protocols) and NonTor jobs, retries containers,
honours a STOP file / disk floor / 72 h cap, and writes STATUS.md + manifest.
"""
from __future__ import annotations

import csv
import json
import math
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "2026-10-28_Recapture"
PRE = OUT / "_preflight"
RUNTIME = HERE / "runtime"
RUN_JOB = HERE / "run_job.py"
META = OUT / "_meta"
LOG_DIR = META / "logs"
PROGRESS = META / "progress"
STOP_FILE = META / "STOP"
STATUS_FILE = OUT / "STATUS.md"
TARGET = 5000
MAX_PARALLEL = 5
MAX_RETRIES = 2
RUN_HOURS = 72
DISK_MIN_GB = 50


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [supervisor] {msg}"
    print(line, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "supervisor.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for line in f if line.strip() and not line.startswith("#"))


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


def build_jobs() -> list[dict]:
    jobs: list[dict] = []
    for proto in ("vless", "anytls", "hysteria2", "trojan"):
        reach = PRE / f"reachable_{proto}.txt"
        n = count_lines(reach)
        if n == 0:
            log(f"{proto}: no reachable targets, skipping pure job")
            continue
        if not (RUNTIME / f"pure-{proto}" / "mihomo.json").is_file():
            log(f"{proto}: no runtime config, skipping")
            continue
        max_site = min(15, max(3, math.ceil(TARGET / n) + 1))
        jobs.append(
            {
                "job": f"pure-{proto}",
                "mode": "pure",
                "protocol": proto,
                "base": f"Pure_Proxy/{proto}",
                "site_list": reach,
                "target": TARGET,
                "max_per_site": max_site,
                "request_timeout": 15,
                "name": f"rc-pure-{proto}",
            }
        )
        log(
            f"{proto}: reachable={n}, max/site={max_site}, "
            f"theoretical={min(TARGET, n * max_site)}"
        )

    direct = PRE / "direct_reachable.txt"
    nd = count_lines(direct)
    if nd > 0:
        jobs.append(
            {
                "job": "nontor",
                "mode": "nontor",
                "protocol": "NonTor",
                "base": "Tor_Direct/NonTor",
                "site_list": direct,
                "target": TARGET,
                "max_per_site": min(12, max(6, math.ceil(TARGET / nd) + 1)),
                "request_timeout": 12,
                "name": "rc-nontor",
            }
        )
        log(
            f"nontor: reachable={nd}, max/site={jobs[-1]['max_per_site']}"
        )
    else:
        log("nontor: no directly reachable targets, skipping")
    return jobs


def launch(job: dict) -> bool:
    cmd = [
        sys.executable,
        str(RUN_JOB),
        "--job",
        job["job"],
        "--mode",
        job["mode"],
        "--protocol",
        job["protocol"],
        "--base-subdir",
        job["base"],
        "--target",
        str(job["target"]),
        "--max-per-site",
        str(job["max_per_site"]),
        "--site-list",
        str(job["site_list"]),
        "--output",
        str(OUT),
        "--runtime",
        str(RUNTIME),
        "--name",
        job["name"],
        "--request-timeout",
        str(job["request_timeout"]),
        "--run-hours",
        str(RUN_HOURS),
    ]
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if p.returncode != 0:
        log(f"launch {job['job']} failed: {p.stderr.strip()[:400]}")
        return False
    log(f"launched {job['job']} ({job['name']})")
    return True


def progress_name(job: str) -> str:
    """Map supervisor job id to capture.py's f'{MODE}__{PROTOCOL}' filename."""
    if job == "nontor":
        return "nontor__NonTor.json"
    if job.startswith("pure-"):
        return f"pure__{job[len('pure-'):]}.json"
    if job.startswith("top-"):
        return f"top__{job[len('top-'):]}.json"
    if job.startswith("pairs-"):
        return f"pairs__{job[len('pairs-'):]}.json"
    return f"{job}.json"


def read_progress(job: str) -> dict:
    p = PROGRESS / progress_name(job)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_status(running: dict, done: set, failed: dict, jobs: dict) -> None:
    lines = [
        "# Recapture status",
        "",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%S%z')}",
        "",
        "| Job | Status | Captured | Target | Attempts | Sites | Node | Last error |",
        "|---|---|---:|---:|---:|---:|---|---|",
    ]
    for job_id in [j["job"] for j in jobs.values()]:
        if job_id in done:
            status = "done"
        elif job_id in failed:
            status = f"failed({failed[job_id]})"
        elif job_id in running:
            status = "running"
        else:
            status = "pending"
        pr = read_progress(job_id)
        lines.append(
            f"| {job_id} | {status} | {pr.get('captured', 0)} | "
            f"{pr.get('target', TARGET)} | {pr.get('attempts', 0)} | "
            f"{pr.get('sites_done', 0)}/{pr.get('sites_total', '?')} | "
            f"{pr.get('current_node', '')} | "
            f"{str(pr.get('last_error', ''))[:100]} |"
        )
    lines += [
        "",
        "Missing modes/protocols: see MISSING_AND_NEXT_STEPS.md",
        f"STOP file: {STOP_FILE}",
        "",
    ]
    STATUS_FILE.write_text("\n".join(lines), encoding="utf-8")


def write_manifest() -> int:
    rows = []
    for base, mode, protocol, pattern in (
        (OUT / "Pure_Proxy", "pure", None, "*.pcap"),
        (OUT / "Tor_Direct" / "NonTor", "nontor", "NonTor", "*.pcap"),
    ):
        if not base.is_dir():
            continue
        for pcap in sorted(base.rglob(pattern)):
            rel = pcap.relative_to(OUT)
            parts = rel.parts
            if mode == "pure":
                proto = parts[1]
                domain = parts[2]
            else:
                proto = "NonTor"
                domain = parts[2]
            rows.append(
                {
                    "mode": mode,
                    "protocol": proto,
                    "domain": domain,
                    "file": str(rel).replace("\\", "/"),
                    "bytes": pcap.stat().st_size,
                }
            )
    path = OUT / "MANIFEST.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["mode", "protocol", "domain", "file", "bytes"]
        )
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PROGRESS.mkdir(parents=True, exist_ok=True)
    if STOP_FILE.exists():
        STOP_FILE.unlink()

    jobs_list = build_jobs()
    if not jobs_list:
        log("no jobs to run")
        return 1
    jobs = {j["job"]: j for j in jobs_list}
    pending = list(jobs)
    running: dict[str, dict] = {}
    done: set[str] = set()
    failed: dict[str, int] = {}
    retries: dict[str, int] = {j: 0 for j in jobs}
    started = time.time()

    # Adopt containers left running by a previous supervisor instance.
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

    log(f"jobs: {[j['job'] for j in jobs_list]}")
    while pending or running:
        if STOP_FILE.exists():
            log("STOP file detected; stopping running jobs")
            for jid, job in running.items():
                docker("stop", job["name"], timeout=60)
            break
        if RUN_HOURS > 0 and time.time() - started > RUN_HOURS * 3600:
            log("72h cap reached; stopping")
            for jid, job in running.items():
                docker("stop", job["name"], timeout=60)
            break
        try:
            free_gb = shutil.disk_usage(str(OUT)).free / (1024 ** 3)
        except Exception:
            free_gb = 10 ** 9
        if free_gb < DISK_MIN_GB:
            log(f"disk low ({free_gb:.1f} GB); stopping")
            for jid, job in running.items():
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
                            # Keep monitoring the new container.
                            pass
                        else:
                            pending.append(jid)
                            running.pop(jid, None)
                    else:
                        failed[jid] = retries[jid]
                        running.pop(jid, None)

        write_status(running, done, failed, jobs)
        time.sleep(30)

    write_status(running, done, failed, jobs)
    n = write_manifest()
    final = [
        "# Recapture final report",
        "",
        f"Finished: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        f"Elapsed: {(time.time()-started)/3600:.1f} h",
        f"Manifest rows: {n}",
        "",
        "| Job | Result |",
        "|---|---|",
    ]
    for jid in jobs:
        result = "done" if jid in done else f"failed/not-complete({failed.get(jid, 0)})"
        final.append(f"| {jid} | {result} |")
    final += [
        "",
        "Tor_over_Proxy / Traffic_Pairs were not run: Tor bootstrap failed through",
        "all available nodes (stuck at 10%) and obfs4 bridges were unreachable.",
        "SS/Mieru were not run: zero working nodes in the tested sources.",
        "VMess was deferred by the user.",
        "",
        "See NODE_TEST_REPORT.md and MISSING_AND_NEXT_STEPS.md.",
    ]
    (OUT / "FINAL_REPORT.md").write_text("\n".join(final) + "\n", encoding="utf-8")
    log(f"supervisor done; manifest rows={n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
