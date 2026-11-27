#!/usr/bin/env python3
"""fix_all.py - coordinated remediation: AppSec + IaC, ONE report, ONE exit code, ONE rollback boundary.

Stages (in order):
  1. appsec            Semgrep report -> scripts/generate_security_pr.py --mode appsec --dry-run
                       (AppSec fixes are delivered as a separate PR; this stage only reports them)
  2. checkov-autofixer PR #15 terraform_autofixer.py, driven by --findings (Checkov/Conftest JSON)
  3. graph-fixer       terraform_graph_fixer: multi-file graph policies (G1-G3), tflint gate

Everything stage 2 and 3 touch is snapshotted up front. Any failure (stage error, failed
fmt/validate/tflint, a "dry-run" that mutated files) restores ALL files byte-for-byte.
Exit codes: 0 ok, 1 failed and rolled back, 2 refused (bad input, nothing touched).
"""
from __future__ import annotations

import argparse
import functools
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import terraform_graph_fixer as g  # noqa: E402

APPSEC_RE = re.compile(r"Auto-fixable findings:\s*(\d+)\s*\|\s*Report-only:\s*(\d+)")


class StageFailed(Exception):
    pass


def run_appsec(report: Path | None) -> dict:
    if report is None or not report.exists():
        return {"stage": "appsec", "status": "SKIPPED", "detail": "no Semgrep report"}
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_security_pr.py"),
         "--mode", "appsec", "--dry-run", "--report", str(report)],
        capture_output=True, text=True, cwd=ROOT)
    m = APPSEC_RE.search(r.stdout)
    if r.returncode != 0 or not m:
        return {"stage": "appsec", "status": "FAIL", "detail": (r.stdout + r.stderr).strip()[-500:]}
    return {"stage": "appsec", "status": "OK", "auto_fixable": int(m.group(1)),
            "report_only": int(m.group(2)),
            "detail": "dry-run only: AppSec fixes are delivered as a separate PR"}


def run_findings_autofixer(a, tf_dir: Path, summary: Path) -> tuple[int, dict]:
    cmd = [sys.executable, str(a.autofixer), "--tf-dir", str(tf_dir), "--summary", str(summary),
           "--validate-mode", a.validate_mode, "--admin-cidr", a.admin_cidr]
    if a.kms_key_arn:
        cmd += ["--kms-key-arn", a.kms_key_arn]
    for f in a.findings:
        cmd += ["--findings", str(f)]
    if not a.apply:
        cmd.append("--dry-run")
    r = subprocess.run(cmd, capture_output=True, text=True)
    data = json.loads(summary.read_text()) if summary.exists() else {}
    if r.returncode != 0:
        data["stderr"] = (r.stdout + r.stderr).strip()[-500:]
    return r.returncode, data


def _changed(tf_dir: Path, snap: dict) -> bool:
    now = {p: p.read_bytes() for p in tf_dir.glob("*.tf")}
    if set(now) != {p for p in snap if p.suffix == ".tf"}:
        return True
    return any(snap[p][0] != now[p] for p in now)


def rollback_all(tf_dir: Path, snap: dict, paths: set) -> None:
    g._restore(snap, paths)
    for p in tf_dir.glob("*.tf"):
        if p not in snap:
            p.unlink()  # created by a stage


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tf-dir", required=True, type=Path)
    ap.add_argument("--appsec-report", type=Path)
    ap.add_argument("--findings", nargs="*", default=[], help="Checkov/Conftest JSON for terraform_autofixer.py")
    ap.add_argument("--autofixer", type=Path, default=ROOT / "terraform_autofixer.py")
    ap.add_argument("--apply", action="store_true", help="apply (default: dry-run, nothing is written)")
    ap.add_argument("--egress-profile", default="tcp/443")
    ap.add_argument("--admin-cidr", default="10.0.0.0/8")
    ap.add_argument("--kms-key-arn")
    ap.add_argument("--validate-mode", choices=["full", "offline"], default="full")
    ap.add_argument("--tflint-config", type=Path)
    ap.add_argument("--report", type=Path)
    a = ap.parse_args(argv)

    tf_dir = a.tf_dir.resolve()
    report: dict = {"mode": "all", "tf_dir": str(tf_dir), "applied": False, "rolled_back": False,
                    "stages": [], "findings": [], "checks": [], "exit_code": 0}

    def finish(rc: int) -> int:
        report["exit_code"] = rc
        manual = sum(1 for f in report["findings"] if f.get("class") == "MANUAL")
        auto = sum(1 for f in report["findings"] if f.get("class") == "AUTO")
        for s in report["stages"]:
            print(f"[{s['status']:7}] {s['stage']}: {s.get('detail', '')}")
        print(f"findings: {len(report['findings'])} (AUTO {auto}, MANUAL {manual}) | "
              f"applied={report['applied']} rolled_back={report['rolled_back']} exit={rc}")
        if a.report:
            a.report.write_text(json.dumps(report, indent=2))
        return rc

    try:
        profile = g.parse_profile(a.egress_profile)
    except ValueError as e:
        report["error"] = str(e)
        return finish(2)
    idx = g.index_dir(tf_dir)
    if idx.duplicates or idx.errors or not tf_dir.is_dir():
        report["error"] = "duplicate addresses or unparsable files; refusing to touch anything"
        return finish(2)

    stage = run_appsec(a.appsec_report)
    report["stages"].append(stage)
    if stage["status"] == "FAIL":
        return finish(1)

    snap, paths = g._snapshot(tf_dir, [])
    try:
        if a.findings:
            with tempfile.TemporaryDirectory() as td:
                rc, summary = run_findings_autofixer(a, tf_dir, Path(td) / "summary.json")
            for r in summary.get("results", []):
                st = r.get("status", "")
                report["findings"].append({
                    "stage": "checkov-autofixer", "rule": r.get("rule"), "address": r.get("resource"),
                    "class": "AUTO" if st == "applied" else "MANUAL" if st == "manual" else st.upper(),
                    "action_or_guidance": r.get("detail")})
            report["stages"].append({"stage": "checkov-autofixer", "status": "OK" if rc == 0 else "FAIL",
                                     "detail": f"exit {rc}"})
            if rc != 0:
                raise StageFailed(f"terraform_autofixer.py exited {rc}")
            if not a.apply and _changed(tf_dir, snap):
                raise StageFailed("autofixer modified files during a dry-run")
        else:
            report["stages"].append({"stage": "checkov-autofixer", "status": "SKIPPED", "detail": "no --findings"})

        _, found = g.plan_fixes(tf_dir, profile)
        edits = [e for f in found if f.cls == "AUTO" for e in f.edits]
        report["findings"] += [{"stage": "graph-fixer", **f.to_dict()} for f in found]
        if a.apply:
            cfg = a.tflint_config or (ROOT / ".tflint.hcl" if (ROOT / ".tflint.hcl").exists() else None)
            check = functools.partial(g.run_checks, tflint_config=cfg)
            if edits:
                results = g.apply_transaction(edits, tf_dir, checks=check)
            else:
                results = check(tf_dir)  # still gate the final state (stage 2 may have changed files)
                if any(r.status == "FAIL" for r in results):
                    raise g.CheckFailed(results)
            report["checks"] = [r.__dict__ for r in results]
            report["applied"] = True
        report["stages"].append({"stage": "graph-fixer", "status": "OK",
                                 "detail": f"{len(edits)} edit(s) {'applied' if a.apply else 'planned'}"})
    except (StageFailed, g.CheckFailed, g.EditError, OSError) as e:
        rollback_all(tf_dir, snap, paths)
        report["rolled_back"], report["applied"], report["error"] = True, False, str(e)
        if isinstance(e, g.CheckFailed):
            report["checks"] = [r.__dict__ for r in e.results]
        report["stages"].append({"stage": "rollback", "status": "OK", "detail": f"all files restored: {e}"})
        return finish(1)
    return finish(0)


if __name__ == "__main__":
    raise SystemExit(main())
