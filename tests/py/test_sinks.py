import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from terraform_graph_fixer import CheckResult, apply_transaction, plan_fixes  # noqa: E402

DB = 'resource "aws_db_instance" "main" {{\n  identifier = "x"\n{extra}}}\n'
EBS = 'resource "aws_ebs_volume" "v" {{\n  size = 1\n{extra}}}\n'


def write(tmp_path, text):
    p = tmp_path / "storage.tf"
    p.write_text(text)
    return p


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.mark.parametrize("tpl,addr,attr", [
    (DB, "aws_db_instance.main", "storage_encrypted"),
    (EBS, "aws_ebs_volume.v", "encrypted"),
])
def test_unencrypted_sink_is_manual_and_never_modified(tmp_path, tpl, addr, attr):
    for extra in ["", f"  {attr} = false\n"]:
        p = write(tmp_path, tpl.format(extra=extra))
        before = sha(p)
        f = plan_fixes(tmp_path)[1]
        assert [(x.address, x.cls, x.edits) for x in f] == [(addr, "MANUAL", [])]
        assert "forces" in f[0].guidance and "replacement" in f[0].guidance
        apply_transaction([e for x in f for e in x.edits], tmp_path, checks=lambda _: [CheckResult("s", "PASS")])
        assert sha(p) == before


@pytest.mark.parametrize("tpl,attr", [(DB, "storage_encrypted"), (EBS, "encrypted")])
def test_encrypted_or_unresolvable_sink_not_reported(tmp_path, tpl, attr):
    for extra in [f"  {attr} = true\n", f"  {attr} = var.enc\n"]:
        write(tmp_path, tpl.format(extra=extra))
        assert plan_fixes(tmp_path)[1] == []


def test_commented_out_flag_does_not_count(tmp_path):
    write(tmp_path, DB.format(extra="  # storage_encrypted = true\n"))
    assert [x.address for x in plan_fixes(tmp_path)[1]] == ["aws_db_instance.main"]


def test_real_fixture_reports_db_and_ebs_as_manual():
    d = Path(__file__).resolve().parents[1] / "fixtures" / "bad"
    if not d.exists():
        pytest.skip("fixture dir missing")
    got = {x.address: x.cls for x in plan_fixes(d)[1]}
    assert got["aws_db_instance.main"] == "MANUAL" and got["aws_ebs_volume.scratch"] == "MANUAL"
    assert got["aws_iam_role.deployer"] == "MANUAL" and got["aws_s3_bucket.data"] == "AUTO"
