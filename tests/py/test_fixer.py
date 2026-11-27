import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import terraform_graph_fixer as tfg  # noqa: E402
from terraform_graph_fixer import (  # noqa: E402
    CheckFailed, CheckResult, Edit, EditError, apply_edits_to_bytes, apply_transaction,
    compute_new_contents, index_dir, main, plan_fixes, run_checks,
)

BUCKET = 'resource "aws_s3_bucket" "{n}" {{\n  bucket = "b-{n}"\n}}\n'


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(d: Path) -> dict:
    return {p.name: sha(p) for p in sorted(d.iterdir()) if p.is_file()}


def ok_checks(_):
    return [CheckResult("stub", "PASS")]


def bad_checks(_):
    return [CheckResult("fmt", "PASS"), CheckResult("validate", "FAIL", "boom")]


# ---------------- edit engine ----------------
def test_descending_application_keeps_offsets_valid():
    data = b"aaaa bbbb cccc"
    p = Path("x")
    out = apply_edits_to_bytes(data, [Edit(p, 0, 4, "AA"), Edit(p, 10, 14, "CCCCCC")])
    assert out == b"AA bbbb CCCCCC"


def test_overlapping_edits_rejected():
    p = Path("x")
    with pytest.raises(EditError):
        apply_edits_to_bytes(b"0123456789", [Edit(p, 2, 6, "x"), Edit(p, 4, 8, "y")])


def test_two_inserts_same_offset_rejected_by_engine_but_merged_by_planner(tmp_path):
    p = tmp_path / "a.tf"
    p.write_bytes(b"x\n")
    with pytest.raises(EditError):
        apply_edits_to_bytes(b"x\n", [Edit(p, 2, 2, "A"), Edit(p, 2, 2, "B")])
    out = compute_new_contents([Edit(p, 2, 2, "A"), Edit(p, 2, 2, "B")])
    assert out[p] == b"x\nAB"


def test_out_of_range_rejected():
    with pytest.raises(EditError):
        apply_edits_to_bytes(b"abc", [Edit(Path("x"), 2, 9, "")])


# ---------------- S3 SSE fixer ----------------
def test_s3_sse_autofix_and_idempotent(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="data"))
    _, f = plan_fixes(tmp_path)
    assert [x.cls for x in f] == ["AUTO"]
    apply_transaction([e for x in f for e in x.edits], tmp_path, checks=ok_checks)
    text = (tmp_path / "main.tf").read_text()
    assert 'resource "aws_s3_bucket_server_side_encryption_configuration" "data" {' in text
    assert "bucket = aws_s3_bucket.data.id" in text
    assert 'sse_algorithm = "AES256"' in text
    _, f2 = plan_fixes(tmp_path)
    assert f2 == []  # second run: no diff


def test_golden_output(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="data"))
    _, f = plan_fixes(tmp_path)
    apply_transaction([e for x in f for e in x.edits], tmp_path, checks=ok_checks)
    assert (tmp_path / "main.tf").read_text() == (
        'resource "aws_s3_bucket" "data" {\n  bucket = "b-data"\n}\n\n'
        'resource "aws_s3_bucket_server_side_encryption_configuration" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n\n"
        "  rule {\n    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm = "AES256"\n    }\n  }\n}\n')


def test_companion_in_other_file_is_recognised(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="data"))
    (tmp_path / "storage.tf").write_text(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "x" {\n'
        "  bucket = aws_s3_bucket.data.id\n}\n")
    assert plan_fixes(tmp_path)[1] == []


def test_reference_inside_comment_does_not_count_as_link(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="data"))
    (tmp_path / "storage.tf").write_text(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "x" {\n'
        "  # bucket = aws_s3_bucket.data.id\n  bucket = aws_s3_bucket.other.id\n}\n")
    f = plan_fixes(tmp_path)[1]
    assert [(x.address, x.cls) for x in f] == [("aws_s3_bucket.data", "AUTO")]


def test_prefix_name_not_confused(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="data") + BUCKET.format(n="data2"))
    (tmp_path / "s.tf").write_text(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "x" {\n'
        "  bucket = aws_s3_bucket.data2.id\n}\n")
    assert [x.address for x in plan_fixes(tmp_path)[1]] == ["aws_s3_bucket.data"]


def test_for_each_bucket_is_manual_and_untouched(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "d" {\n  for_each = toset(["a"])\n  bucket = each.key\n}\n')
    before = snapshot(tmp_path)
    f = plan_fixes(tmp_path)[1]
    assert [(x.cls, x.edits) for x in f] == [("MANUAL", [])]
    assert snapshot(tmp_path) == before


def test_name_collision_uses_suffix(tmp_path):
    (tmp_path / "main.tf").write_text(
        BUCKET.format(n="data")
        + 'resource "aws_s3_bucket_server_side_encryption_configuration" "data" {\n'
        "  bucket = aws_s3_bucket.other.id\n}\n")
    f = plan_fixes(tmp_path)[1]
    assert f[0].cls == "AUTO" and '"data_sse"' in f[0].edits[0].text


def test_two_buckets_same_file_both_fixed(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="a") + BUCKET.format(n="b"))
    f = plan_fixes(tmp_path)[1]
    apply_transaction([e for x in f for e in x.edits], tmp_path, checks=ok_checks)
    idx = index_dir(tmp_path)
    assert f"{tfg.SSE_TYPE}.a" in idx.blocks and f"{tfg.SSE_TYPE}.b" in idx.blocks


def test_missing_trailing_newline_and_crlf(tmp_path):
    (tmp_path / "a.tf").write_bytes(b'resource "aws_s3_bucket" "a" {\r\n}')
    f = plan_fixes(tmp_path)[1]
    apply_transaction([e for x in f for e in x.edits], tmp_path, checks=ok_checks)
    data = (tmp_path / "a.tf").read_bytes()
    assert b"\r\n\r\nresource" in data and b"\n" not in data.replace(b"\r\n", b"")
    assert plan_fixes(tmp_path)[1] == []


# ---------------- G1 classifier ----------------
G1_TF = '''resource "aws_iam_role" "r" {
  name = "r"
}

resource "aws_iam_role_policy" "a" {
  role = aws_iam_role.r.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }]
  })
}
'''
G1_TF2 = '''resource "aws_iam_role_policy" "b" {
  role = aws_iam_role.r.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["lambda:CreateFunction"], Resource = "*" }]
  })
}
'''


def test_g1_cross_file_pair_is_manual_and_files_byte_identical(tmp_path):
    (tmp_path / "iam.tf").write_text(G1_TF)
    (tmp_path / "iam2.tf").write_text(G1_TF2)
    before = snapshot(tmp_path)
    f = plan_fixes(tmp_path)[1]
    assert [(x.rule, x.address, x.cls, x.edits) for x in f] == [
        ("G1-privesc-pair", "aws_iam_role.r", "MANUAL", [])]
    assert "iam:PassedToService" in f[0].guidance
    assert apply_transaction([], tmp_path, checks=ok_checks)
    assert snapshot(tmp_path) == before


def test_g1_passrole_alone_not_flagged(tmp_path):
    (tmp_path / "iam.tf").write_text(G1_TF)
    assert plan_fixes(tmp_path)[1] == []


def test_g1_wildcard_action_flagged(tmp_path):
    (tmp_path / "iam.tf").write_text(G1_TF.replace("iam:PassRole", "*"))
    assert [x.rule for x in plan_fixes(tmp_path)[1]] == ["G1-privesc-pair"]


def test_g1_resource_star_is_not_treated_as_action_wildcard(tmp_path):
    # D18 regression: Resource = "*" must not count as Action = "*"
    (tmp_path / "iam.tf").write_text(G1_TF + G1_TF2.replace("lambda:CreateFunction", "s3:GetObject"))
    assert plan_fixes(tmp_path)[1] == []


def test_g1_json_style_action_key_in_heredoc(tmp_path):
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.r.id\n  policy = <<EOT\n'
        '{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]}\nEOT\n}\n')
    assert [x.rule for x in plan_fixes(tmp_path)[1]] == ["G1-privesc-pair"]


# ---------------- rollback proofs ----------------
def two_file_dir(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="a"))
    (tmp_path / "other.tf").write_text(BUCKET.format(n="b"))
    return [e for x in plan_fixes(tmp_path)[1] for e in x.edits]


def test_rollback_restores_all_files_after_failed_check(tmp_path):
    edits = two_file_dir(tmp_path)
    assert len({e.path for e in edits}) == 2
    before = snapshot(tmp_path)
    with pytest.raises(CheckFailed):
        apply_transaction(edits, tmp_path, checks=bad_checks)
    assert snapshot(tmp_path) == before
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".*.tmp"))


def test_rollback_when_write_fails_after_first_file_written(tmp_path, monkeypatch):
    edits = two_file_dir(tmp_path)
    before = snapshot(tmp_path)
    real = tfg._atomic_write
    calls = {"n": 0}

    def flaky(path, data, mode=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real(path, data, mode)

    monkeypatch.setattr(tfg, "_atomic_write", flaky)
    with pytest.raises(OSError):
        apply_transaction(edits, tmp_path, checks=ok_checks)
    assert calls["n"] >= 3  # 1 ok, 2 failed, then restore wrote the first file back
    assert snapshot(tmp_path) == before


def test_created_file_is_removed_on_rollback(tmp_path):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="a"))
    new = tmp_path / "extra.tf"
    before = snapshot(tmp_path)
    with pytest.raises(CheckFailed):
        apply_transaction([Edit(new, 0, 0, "# new\n")], tmp_path, checks=bad_checks)
    assert not new.exists() and snapshot(tmp_path) == before


def test_file_mode_preserved_through_rollback(tmp_path):
    edits = two_file_dir(tmp_path)
    os.chmod(tmp_path / "main.tf", 0o600)
    with pytest.raises(CheckFailed):
        apply_transaction(edits, tmp_path, checks=bad_checks)
    assert stat.S_IMODE((tmp_path / "main.tf").stat().st_mode) == 0o600


def test_overlap_error_touches_nothing(tmp_path):
    (tmp_path / "main.tf").write_text("0123456789\n")
    before = snapshot(tmp_path)
    p = tmp_path / "main.tf"
    with pytest.raises(EditError):
        apply_transaction([Edit(p, 1, 5, "x"), Edit(p, 3, 7, "y")], tmp_path, checks=ok_checks)
    assert snapshot(tmp_path) == before


@pytest.fixture
def shim(tmp_path_factory, monkeypatch):
    d = tmp_path_factory.mktemp("shim")
    tfp = d / "terraform"
    tfp.write_text('#!/bin/sh\ncase "$1" in\n  fmt) exit ${FMT_RC:-0};;\n'
                   '  init) exit ${INIT_RC:-0};;\n  validate) exit ${VAL_RC:-0};;\nesac\nexit 0\n')
    tfp.chmod(0o755)
    tl = d / "tflint"  # hermetic: never run a real tflint from tests
    tl.write_text("#!/bin/sh\nexit ${TFLINT_RC:-0}\n")
    tl.chmod(0o755)
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    return d


@pytest.mark.parametrize("var,name", [("FMT_RC", "fmt"), ("VAL_RC", "validate")])
def test_rollback_via_fake_terraform_shim(tmp_path, shim, monkeypatch, var, name):
    edits = two_file_dir(tmp_path)
    before = snapshot(tmp_path)
    monkeypatch.setenv(var, "1")
    with pytest.raises(CheckFailed) as ei:
        apply_transaction(edits, tmp_path)
    assert [r.name for r in ei.value.results if r.status == "FAIL"] == [name]
    assert snapshot(tmp_path) == before


def test_rollback_on_tflint_failure(tmp_path, shim, monkeypatch):
    monkeypatch.setenv("TFLINT_RC", "1")
    edits = two_file_dir(tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(CheckFailed) as ei:
        apply_transaction(edits, tmp_path)
    assert ei.value.results[-1].name == "tflint"
    assert snapshot(tmp_path) == before


def test_success_path_with_shim_persists_changes(tmp_path, shim):
    edits = two_file_dir(tmp_path)
    before = snapshot(tmp_path)
    results = apply_transaction(edits, tmp_path)
    assert all(r.status in ("PASS", "SKIPPED") for r in results)
    assert snapshot(tmp_path) != before


def test_missing_terraform_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "nonexistent"))
    r = run_checks(tmp_path)
    assert r[0].status == "FAIL"


# ---------------- CLI ----------------
def test_cli_dry_run_is_default_and_changes_nothing(tmp_path, capsys):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="a"))
    before = snapshot(tmp_path)
    assert main(["--tf-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "[AUTO]" in out and "+resource" in out
    assert snapshot(tmp_path) == before


def test_cli_apply_rolls_back_and_exits_1(tmp_path, shim, monkeypatch):
    (tmp_path / "main.tf").write_text(BUCKET.format(n="a"))
    before = snapshot(tmp_path)
    monkeypatch.setenv("VAL_RC", "1")
    rep = tmp_path.parent / "report.json"
    assert main(["--tf-dir", str(tmp_path), "--apply", "--report", str(rep)]) == 1
    assert snapshot(tmp_path) == before
    assert '"FAIL"' in rep.read_text()


def test_cli_refuses_on_duplicates(tmp_path, capsys):
    (tmp_path / "a.tf").write_text(BUCKET.format(n="x"))
    (tmp_path / "b.tf").write_text(BUCKET.format(n="x"))
    before = snapshot(tmp_path)
    assert main(["--tf-dir", str(tmp_path), "--apply"]) == 2
    assert snapshot(tmp_path) == before


def test_tflint_absent_is_reported_as_skipped(tmp_path, shim, monkeypatch):
    (shim / "tflint").unlink()
    monkeypatch.setenv("PATH", str(shim))  # shim dir only: no real tflint reachable
    results = run_checks(tmp_path)
    assert [(r.name, r.status) for r in results] == [
        ("fmt", "PASS"), ("init", "PASS"), ("validate", "PASS"), ("tflint", "SKIPPED")]


def test_tflint_receives_absolute_config_path(tmp_path, shim):
    log = tmp_path.parent / "tflint_args.txt"
    (shim / "tflint").write_text(f'#!/bin/sh\necho "$@" > {log}\nexit 0\n')
    cfg = tmp_path.parent / "my.tflint.hcl"
    cfg.write_text("")
    results = run_checks(tmp_path, tflint_config=cfg)
    assert results[-1].status == "PASS"
    args = log.read_text()
    assert f"--chdir={tmp_path}" in args and f"--config={cfg.resolve()}" in args


def test_tflint_without_config_gets_no_config_flag(tmp_path, shim):
    log = tmp_path.parent / "tflint_args2.txt"
    (shim / "tflint").write_text(f'#!/bin/sh\necho "$@" > {log}\nexit 0\n')
    run_checks(tmp_path)
    assert "--config" not in log.read_text()
