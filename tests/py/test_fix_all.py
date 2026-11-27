import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("fix_all", ROOT / "scripts" / "fix_all.py")
fix_all = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix_all)

MAIN = 'resource "aws_s3_bucket" "a" {\n  bucket = "a"\n}\n'
NET = '''resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = "sg-1"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
'''
FAKE = '''import argparse, json, os, pathlib
ap = argparse.ArgumentParser()
ap.add_argument("--tf-dir"); ap.add_argument("--summary"); ap.add_argument("--validate-mode")
ap.add_argument("--admin-cidr"); ap.add_argument("--kms-key-arn")
ap.add_argument("--findings", action="append"); ap.add_argument("--dry-run", action="store_true")
a = ap.parse_args()
mode = os.environ.get("FAKE_MODE", "ok")
d = pathlib.Path(a.tf_dir)
if mode == "mutate_in_dry_run" or not a.dry_run:
    f = d / "main.tf"
    f.write_text(f.read_text() + "# touched by stage 2\\n")
    (d / "created_by_stage2.tf").write_text("# new file\\n")
pathlib.Path(a.summary).write_text(json.dumps({"results": [
    {"rule": "S3_ENCRYPTION", "resource": "aws_s3_bucket.a", "source": "checkov:CKV_AWS_145",
     "status": "applied", "detail": "fake"},
    {"rule": "IAM_WILDCARD", "resource": "aws_iam_role_policy.x", "source": "opa",
     "status": "manual", "detail": "human"}], "files_changed": ["main.tf"], "validated": True}))
raise SystemExit(1 if mode == "fail" else 0)
'''


def sha_dir(d: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.iterdir()) if p.is_file()}


@pytest.fixture
def env(tmp_path, tmp_path_factory, monkeypatch):
    work = tmp_path / "tf"
    work.mkdir()
    (work / "main.tf").write_text(MAIN)
    (work / "network.tf").write_text(NET)
    fake = tmp_path / "fake_autofixer.py"
    fake.write_text(FAKE)
    findings = tmp_path / "findings.json"
    findings.write_text("{}")
    shim = tmp_path_factory.mktemp("shim")
    for name, body in {
        "terraform": '#!/bin/sh\\ncase "$1" in\\n  fmt) exit ${FMT_RC:-0};;\\n  init) exit 0;;\\n  validate) exit ${VAL_RC:-0};;\\nesac\\nexit 0\\n',
        "tflint": "#!/bin/sh\\nexit ${TFLINT_RC:-0}\\n",
    }.items():
        (shim / name).write_text(body.replace("\\n", "\n"))
        (shim / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}:{os.environ['PATH']}")
    return {"work": work, "fake": fake, "findings": findings, "report": tmp_path / "r.json"}


def run(env, *extra):
    args = ["--tf-dir", str(env["work"]), "--autofixer", str(env["fake"]),
            "--findings", str(env["findings"]), "--report", str(env["report"]), *extra]
    rc = fix_all.main(args)
    return rc, json.loads(env["report"].read_text())


def test_dry_run_writes_nothing_and_merges_both_stages(env):
    before = sha_dir(env["work"])
    rc, rep = run(env)
    assert rc == 0 and sha_dir(env["work"]) == before
    assert {f["stage"] for f in rep["findings"]} == {"checkov-autofixer", "graph-fixer"}
    assert rep["applied"] is False and rep["exit_code"] == 0


def test_apply_runs_both_stages_in_one_boundary(env):
    rc, rep = run(env, "--apply")
    assert rc == 0 and rep["applied"] is True
    assert "# touched by stage 2" in (env["work"] / "main.tf").read_text()
    assert 'ip_protocol       = "tcp"' in (env["work"] / "network.tf").read_text()
    assert "aws_s3_bucket_server_side_encryption_configuration" in (env["work"] / "main.tf").read_text()
    assert [c["status"] for c in rep["checks"]][:3] == ["PASS", "PASS", "PASS"]


def test_stage2_failure_rolls_back_everything_and_skips_stage3(env, monkeypatch):
    before = sha_dir(env["work"])
    monkeypatch.setenv("FAKE_MODE", "fail")
    rc, rep = run(env, "--apply")
    assert rc == 1 and rep["rolled_back"] is True
    assert sha_dir(env["work"]) == before  # incl. the file stage 2 created is gone
    assert not any(s["stage"] == "graph-fixer" for s in rep["stages"])


def test_stage3_check_failure_rolls_back_stage2_too(env, monkeypatch):
    """Cross-stage rollback proof: stage 2 succeeded and wrote files; stage 3's gate fails."""
    before = sha_dir(env["work"])
    monkeypatch.setenv("VAL_RC", "1")
    rc, rep = run(env, "--apply")
    assert rc == 1 and rep["rolled_back"] is True
    assert sha_dir(env["work"]) == before
    assert not (env["work"] / "created_by_stage2.tf").exists()
    assert any(c["status"] == "FAIL" for c in rep["checks"])


def test_tflint_failure_also_rolls_back_both_stages(env, monkeypatch):
    before = sha_dir(env["work"])
    monkeypatch.setenv("TFLINT_RC", "1")
    rc, _ = run(env, "--apply")
    assert rc == 1 and sha_dir(env["work"]) == before


def test_autofixer_that_mutates_during_dry_run_is_caught_and_reverted(env, monkeypatch):
    before = sha_dir(env["work"])
    monkeypatch.setenv("FAKE_MODE", "mutate_in_dry_run")
    rc, rep = run(env)
    assert rc == 1 and sha_dir(env["work"]) == before and "dry-run" in rep["error"]


def test_duplicate_addresses_refused_untouched(env):
    (env["work"] / "dup.tf").write_text(MAIN)
    before = sha_dir(env["work"])
    rc, rep = run(env, "--apply")
    assert rc == 2 and sha_dir(env["work"]) == before


def test_no_findings_skips_stage2_but_graph_stage_runs(env):
    rc = fix_all.main(["--tf-dir", str(env["work"]), "--report", str(env["report"]), "--apply"])
    rep = json.loads(env["report"].read_text())
    assert rc == 0
    assert [s["status"] for s in rep["stages"] if s["stage"] == "checkov-autofixer"] == ["SKIPPED"]
    assert 'ip_protocol       = "tcp"' in (env["work"] / "network.tf").read_text()


def test_bad_profile_refused(env):
    rc, _ = run(env, "--egress-profile", "icmp/1")
    assert rc == 2


def test_appsec_stage_skipped_without_report_and_regex_parses():
    assert fix_all.run_appsec(None)["status"] == "SKIPPED"
    m = fix_all.APPSEC_RE.search("noise\nAuto-fixable findings: 3 | Report-only: 5\n")
    assert (m.group(1), m.group(2)) == ("3", "5")
