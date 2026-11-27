import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from terraform_graph_fixer import ScanError, index_dir, scan_blocks  # noqa: E402


def addrs(src: str) -> list[str]:
    return [b.address for b in scan_blocks(src.encode())]


def test_brace_inside_string():
    assert addrs('resource "a" "b" {\n  x = "}{"\n}\nresource "c" "d" {\n}\n') == ["a.b", "c.d"]


def test_hash_and_slashes_inside_string():
    src = 'resource "a" "b" {\n  u = "http://x/#frag"\n}\nresource "c" "d" {\n}\n'
    assert addrs(src) == ["a.b", "c.d"]


def test_comments_with_braces():
    src = (
        'resource "a" "b" {\n  # }\n  // }\n  /* } */\n}\n'
        'resource "c" "d" {\n}\n'
    )
    assert addrs(src) == ["a.b", "c.d"]


def test_commented_out_resource_is_not_indexed():
    assert addrs('# resource "x" "y" {\n}\nresource "a" "b" {\n}\n') == ["a.b"]


def test_heredoc_containing_resource_text():
    src = (
        'resource "a" "b" {\n  p = <<EOF\nresource "x" "y" {\n}\nEOF\n}\n'
        'resource "c" "d" {\n}\n'
    )
    assert addrs(src) == ["a.b", "c.d"]


def test_indented_heredoc_with_unbalanced_brace():
    src = 'resource "a" "b" {\n  p = <<-EOT\n    {{{\n    EOT\n}\nresource "c" "d" {\n}\n'
    assert addrs(src) == ["a.b", "c.d"]


def test_nested_blocks():
    src = 'resource "a" "b" {\n  egress {\n    x { y = 1 }\n  }\n}\n'
    (b,) = scan_blocks(src.encode())
    assert src.encode()[b.start : b.end].endswith(b"}\n  }\n}")


def test_interpolation_with_nested_quote_and_brace():
    src = 'resource "a" "b" {\n  n = "${var.m["}"]}"\n}\nresource "c" "d" {\n}\n'
    assert addrs(src) == ["a.b", "c.d"]


def test_escaped_interpolation_is_literal():
    src = 'resource "a" "b" {\n  n = "$${"\n}\nresource "c" "d" {\n}\n'
    assert addrs(src) == ["a.b", "c.d"]


def test_crlf_offsets_slice_exactly():
    src = b'resource "a" "b" {\r\n  x = 1\r\n}\r\nresource "c" "d" {\r\n}\r\n'
    blocks = scan_blocks(src)
    assert [b.address for b in blocks] == ["a.b", "c.d"]
    assert src[blocks[0].start : blocks[0].end] == b'resource "a" "b" {\r\n  x = 1\r\n}'
    assert blocks[1].line == 4


def test_body_span():
    src = b'resource "a" "b" {\n  x = 1\n}\n'
    (b,) = scan_blocks(src)
    assert src[b.body_start : b.body_end] == b"\n  x = 1\n"


def test_non_resource_blocks_have_kinds():
    blocks = scan_blocks(b'variable "v" {\n}\ndata "t" "n" {\n}\nlocals {\n}\n')
    assert [b.address for b in blocks] == ["var.v", "data.t.n", "locals"]


def test_unterminated_block_raises():
    with pytest.raises(ScanError):
        scan_blocks(b'resource "a" "b" {\n  x = 1\n')


def test_unterminated_string_raises():
    with pytest.raises(ScanError):
        scan_blocks(b'resource "a" "b" {\n  x = "abc\n}\n')


def test_unterminated_heredoc_raises():
    with pytest.raises(ScanError):
        scan_blocks(b'resource "a" "b" {\n  x = <<EOF\nabc\n}\n')


# ---------------- indexer ----------------
def test_index_across_files(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n}\n')
    (tmp_path / "storage.tf").write_text(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "data" {\n}\n'
    )
    idx = index_dir(tmp_path)
    assert set(idx.blocks) == {
        "aws_s3_bucket.data",
        "aws_s3_bucket_server_side_encryption_configuration.data",
    }
    assert idx.blocks["aws_s3_bucket.data"].path.name == "main.tf"
    assert not idx.duplicates


def test_duplicate_address_reported_not_crashed(tmp_path):
    (tmp_path / "a.tf").write_text('resource "x" "y" {\n}\n')
    (tmp_path / "b.tf").write_text('resource "x" "y" {\n}\n')
    idx = index_dir(tmp_path)
    assert [b.path.name for b in idx.duplicates["x.y"]] == ["a.tf", "b.tf"]


def test_empty_dir(tmp_path):
    idx = index_dir(tmp_path)
    assert idx.blocks == {} and idx.duplicates == {} and idx.errors == {}


def test_bad_file_recorded_other_files_still_indexed(tmp_path):
    (tmp_path / "bad.tf").write_text('resource "a" "b" {\n')
    (tmp_path / "ok.tf").write_text('resource "c" "d" {\n}\n')
    idx = index_dir(tmp_path)
    assert "c.d" in idx.blocks and (tmp_path / "bad.tf") in idx.errors


def test_indexer_ignores_subdirs_and_non_tf(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.tf").write_text('resource "a" "b" {\n}\n')
    (tmp_path / "notes.txt").write_text('resource "a" "b" {\n}\n')
    assert index_dir(tmp_path).blocks == {}


def test_real_fixture_if_present():
    d = Path(__file__).resolve().parents[1] / "fixtures" / "bad"
    if not d.exists():
        pytest.skip("fixture dir missing")
    idx = index_dir(d)
    assert "aws_iam_role.deployer" in idx.blocks
    assert not idx.errors and not idx.duplicates
