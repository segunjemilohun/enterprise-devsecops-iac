import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from terraform_graph_fixer import (  # noqa: E402
    CheckResult, apply_transaction, index_dir, main, parse_profile, plan_fixes,
)

INLINE = '''resource "aws_security_group" "open" {
  name = "open-egress"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
VPC = '''resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.open.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
'''
SGR = '''resource "aws_security_group_rule" "out" {
  type              = "egress"
  security_group_id = aws_security_group.open.id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
}
'''


def ok(_):
    return [CheckResult("stub", "PASS")]


def fix(tmp_path, profile=(("tcp", 443),)):
    f = plan_fixes(tmp_path, profile)[1]
    edits = [e for x in f for e in x.edits]
    if edits:
        apply_transaction(edits, tmp_path, checks=ok)
    return f


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------- AUTO rewrites (golden) ----------------
def test_inline_egress_tightened_in_place(tmp_path):
    p = write(tmp_path, "network.tf", INLINE)
    f = fix(tmp_path)
    assert [x.cls for x in f] == ["AUTO"]
    assert p.read_text() == INLINE.replace('0\n    to_port     = 0', '443\n    to_port     = 443').replace(
        'protocol    = "-1"', 'protocol    = "tcp"')


def test_vpc_rule_gets_ports_inserted_aligned(tmp_path):
    p = write(tmp_path, "network.tf", VPC)
    fix(tmp_path)
    assert p.read_text() == (
        'resource "aws_vpc_security_group_egress_rule" "all" {\n'
        "  security_group_id = aws_security_group.open.id\n"
        '  ip_protocol       = "tcp"\n'
        "  from_port         = 443\n"
        "  to_port           = 443\n"
        '  cidr_ipv4         = "0.0.0.0/0"\n}\n')


def test_security_group_rule_egress_tightened(tmp_path):
    p = write(tmp_path, "network.tf", SGR)
    fix(tmp_path)
    t = p.read_text()
    assert 'protocol          = "tcp"' in t and "from_port         = 443" in t and "to_port           = 443" in t


def test_idempotent_second_run_has_no_findings(tmp_path):
    write(tmp_path, "a.tf", INLINE)
    write(tmp_path, "b.tf", VPC)
    write(tmp_path, "c.tf", SGR)
    assert len(fix(tmp_path)) == 3
    assert plan_fixes(tmp_path)[1] == []


def test_full_tcp_range_is_treated_as_unrestricted(tmp_path):
    t = INLINE.replace('"-1"', '"tcp"').replace("to_port     = 0", "to_port     = 65535")
    p = write(tmp_path, "n.tf", t)
    fix(tmp_path)
    assert "to_port     = 443" in p.read_text() and "65535" not in p.read_text()


def test_ipv6_only_vpc_rule(tmp_path):
    p = write(tmp_path, "n.tf", VPC.replace("cidr_ipv4         = \"0.0.0.0/0\"", "cidr_ipv6         = \"::/0\""))
    fix(tmp_path)
    assert 'ip_protocol       = "tcp"' in p.read_text()


# ---------------- multi-entry profile ----------------
def test_profile_clones_vpc_rule_with_new_names(tmp_path):
    p = write(tmp_path, "n.tf", VPC)
    fix(tmp_path, parse_profile("tcp/443,udp/53"))
    idx = index_dir(tmp_path)
    assert set(idx.blocks) == {
        "aws_vpc_security_group_egress_rule.all",
        "aws_vpc_security_group_egress_rule.all_udp_53"}
    assert 'ip_protocol       = "udp"' in p.read_text() and "from_port         = 53" in p.read_text()
    assert plan_fixes(tmp_path)[1] == []


def test_profile_duplicates_inline_block(tmp_path):
    p = write(tmp_path, "n.tf", INLINE)
    fix(tmp_path, parse_profile("tcp/443,tcp/80"))
    t = p.read_text()
    assert t.count("egress {") == 2 and "= 80" in t and "= 443" in t
    assert plan_fixes(tmp_path)[1] == []


def test_two_open_inline_blocks_in_one_group(tmp_path):
    two = INLINE.replace("  }\n}\n", '  }\n\n  egress {\n    from_port   = 0\n    to_port     = 0\n'
                         '    protocol    = "-1"\n    ipv6_cidr_blocks = ["::/0"]\n  }\n}\n')
    p = write(tmp_path, "n.tf", two)
    f = fix(tmp_path)
    assert [x.cls for x in f] == ["AUTO", "AUTO"] and p.read_text().count('"tcp"') == 2


def test_clone_name_collision_is_manual_and_untouched(tmp_path):
    p = write(tmp_path, "n.tf", VPC + VPC.replace('"all"', '"all_udp_53"').replace('"-1"', '"tcp"'))
    before = sha(p)
    f = plan_fixes(tmp_path, parse_profile("tcp/443,udp/53"))[1]
    assert f and f[0].cls == "MANUAL" and f[0].edits == [] and sha(p) == before


# ---------------- must NOT be touched ----------------
@pytest.mark.parametrize("text", [
    INLINE.replace('"-1"', '"tcp"').replace("from_port   = 0", "from_port   = 443").replace("to_port     = 0", "to_port     = 443"),
    INLINE.replace("0.0.0.0/0", "10.0.0.0/8"),
    INLINE.replace('["0.0.0.0/0"]', "var.cidrs"),
    INLINE.replace('["0.0.0.0/0"]', "[var.cidr]"),
    SGR.replace('"egress"', '"ingress"'),
    VPC.replace('"-1"', '"tcp"'),
    "# " + VPC.replace("\n", "\n# "),
])
def test_safe_or_unprovable_configs_are_untouched(tmp_path, text):
    p = write(tmp_path, "n.tf", text)
    before = sha(p)
    assert plan_fixes(tmp_path)[1] == [] and sha(p) == before


def test_mixed_cidrs_manual(tmp_path):
    p = write(tmp_path, "n.tf", INLINE.replace('["0.0.0.0/0"]', '["0.0.0.0/0", "10.0.0.0/8"]'))
    before = sha(p)
    f = plan_fixes(tmp_path)[1]
    assert [(x.cls, x.edits) for x in f] == [("MANUAL", [])] and "private" in f[0].guidance and sha(p) == before


def test_prefix_list_target_manual(tmp_path):
    t = INLINE.replace('    cidr_blocks = ["0.0.0.0/0"]\n', '    cidr_blocks = ["0.0.0.0/0"]\n    prefix_list_ids = ["pl-1"]\n')
    write(tmp_path, "n.tf", t)
    f = plan_fixes(tmp_path)[1]
    assert [x.cls for x in f] == ["MANUAL"]


def test_count_rule_manual(tmp_path):
    p = write(tmp_path, "n.tf", VPC.replace("{\n", "{\n  count = 2\n", 1))
    f = plan_fixes(tmp_path)[1]
    assert [(x.cls, x.edits) for x in f] == [("MANUAL", [])]


# ---------------- coexistence, CRLF, CLI ----------------
def test_egress_and_sse_edits_in_same_file_do_not_conflict(tmp_path):
    p = write(tmp_path, "main.tf", 'resource "aws_s3_bucket" "d" {\n}\n\n' + VPC)  # block ends at EOF
    f = fix(tmp_path)
    assert sorted(x.rule for x in f) == ["G2-s3-sse", "G3-open-egress"]
    idx = index_dir(tmp_path)
    assert "aws_s3_bucket_server_side_encryption_configuration.d" in idx.blocks
    assert plan_fixes(tmp_path)[1] == []


def test_crlf_vpc_rule(tmp_path):
    p = tmp_path / "n.tf"
    p.write_bytes(VPC.replace("\n", "\r\n").encode())
    fix(tmp_path)
    data = p.read_bytes()
    assert b"from_port         = 443\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")


def test_parse_profile_validation():
    assert parse_profile("tcp/443, udp/53,tcp/443") == (("tcp", 443), ("udp", 53))
    for bad in ["icmp/1", "tcp/0", "tcp/70000", "443", "tcp/"]:
        with pytest.raises(ValueError):
            parse_profile(bad)


def test_cli_rejects_bad_profile_and_dry_run_default(tmp_path, capsys):
    p = write(tmp_path, "n.tf", VPC)
    before = sha(p)
    assert main(["--tf-dir", str(tmp_path), "--egress-profile", "icmp/1"]) == 2
    assert main(["--tf-dir", str(tmp_path), "--egress-profile", "tcp/8443"]) == 0
    assert "8443" in capsys.readouterr().out and sha(p) == before


@pytest.mark.skipif(not shutil.which("terraform"), reason="terraform not installed")
def test_output_is_terraform_fmt_clean(tmp_path):
    write(tmp_path, "a.tf", INLINE)
    write(tmp_path, "b.tf", VPC)
    write(tmp_path, "c.tf", SGR)
    fix(tmp_path, parse_profile("tcp/443,udp/53"))
    r = subprocess.run(["terraform", "fmt", "-check", "-recursive", "-diff"], cwd=tmp_path,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
