#!/usr/bin/env python3
"""terraform_graph_fixer: multi-file, format-preserving Terraform scanner/indexer.

Stage 1 (this file so far): Scanner + Indexer.
All offsets are BYTE offsets into the original file contents.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

IDENT_START = re.compile(rb"[A-Za-z_]")
IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_-]*")
HEREDOC_OPEN = re.compile(rb"<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")


class ScanError(Exception):
    """Raised when a file cannot be tokenized (unterminated string, brace, ...)."""


def _skip_line(data: bytes, i: int) -> int:
    j = data.find(b"\n", i)
    return len(data) if j == -1 else j  # stop AT the newline


def _skip_block_comment(data: bytes, i: int) -> int:
    j = data.find(b"*/", i + 2)
    if j == -1:
        raise ScanError(f"unterminated /* comment at byte {i}")
    return j + 2


def _skip_template(data: bytes, i: int) -> int:
    """i is just after '${' or '%{'. Return the index after the matching '}'."""
    depth = 1
    n = len(data)
    while i < n:
        c = data[i : i + 1]
        if c == b'"':
            i = _skip_string(data, i)
            continue
        if c == b"{":
            depth += 1
        elif c == b"}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ScanError("unterminated template interpolation")


def _skip_string(data: bytes, i: int) -> int:
    """i is at the opening quote. Return the index after the closing quote."""
    start = i
    i += 1
    n = len(data)
    while i < n:
        c = data[i : i + 1]
        if c == b"\\":
            i += 2
            continue
        if c == b'"':
            return i + 1
        if c == b"\n":
            raise ScanError(f"unterminated string starting at byte {start}")
        if data[i : i + 3] in (b"$${", b"%%{"):  # escaped, literal
            i += 3
            continue
        if data[i : i + 2] in (b"${", b"%{"):
            i = _skip_template(data, i + 2)
            continue
        i += 1
    raise ScanError(f"unterminated string starting at byte {start}")


def _skip_heredoc(data: bytes, i: int) -> int | None:
    """If a heredoc opens at i, return the index after its terminator line."""
    m = HEREDOC_OPEN.match(data, i)
    if not m:
        return None
    marker = m.group(2)
    pos = m.end()
    n = len(data)
    while pos < n:
        eol = data.find(b"\n", pos)
        line_end = n if eol == -1 else eol
        if data[pos:line_end].strip() == marker:
            return line_end
        if eol == -1:
            break
        pos = eol + 1
    raise ScanError(f"unterminated heredoc <<{marker.decode()} at byte {i}")


def _find_block_end(data: bytes, open_idx: int) -> int:
    """open_idx is at '{'. Return the index after the matching '}'."""
    depth = 1
    i = open_idx + 1
    n = len(data)
    while i < n:
        c = data[i : i + 1]
        if c == b'"':
            i = _skip_string(data, i)
        elif c == b"#":
            i = _skip_line(data, i)
        elif data[i : i + 2] == b"//":
            i = _skip_line(data, i)
        elif data[i : i + 2] == b"/*":
            i = _skip_block_comment(data, i)
        elif data[i : i + 2] == b"<<":
            end = _skip_heredoc(data, i)
            i = end if end is not None else i + 2
        else:
            if c == b"{":
                depth += 1
            elif c == b"}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
    raise ScanError(f"unterminated block opened at byte {open_idx}")


@dataclass(frozen=True)
class Block:
    path: Path
    kind: str                # resource | data | module | variable | ...
    labels: tuple[str, ...]
    start: int               # first byte of the block keyword
    end: int                 # one past the closing '}'
    body_start: int          # one past the opening '{'
    body_end: int            # index of the closing '}'
    line: int                # 1-based line of `start`

    @property
    def address(self) -> str:
        if self.kind == "resource" and len(self.labels) == 2:
            return f"{self.labels[0]}.{self.labels[1]}"
        if self.kind == "data" and len(self.labels) == 2:
            return f"data.{self.labels[0]}.{self.labels[1]}"
        if self.kind in ("module", "variable", "output") and self.labels:
            prefix = {"module": "module", "variable": "var", "output": "output"}[self.kind]
            return f"{prefix}.{self.labels[0]}"
        return self.kind + ("." + ".".join(self.labels) if self.labels else "")


def scan_blocks(data: bytes, path: Path = Path("<memory>")) -> list[Block]:
    """Return the top-level blocks of one file, with byte offsets."""
    blocks: list[Block] = []
    i, n = 0, len(data)
    while i < n:
        c = data[i : i + 1]
        if c in (b" ", b"\t", b"\r", b"\n"):
            i += 1
        elif c == b"#" or data[i : i + 2] == b"//":
            i = _skip_line(data, i)
        elif data[i : i + 2] == b"/*":
            i = _skip_block_comment(data, i)
        elif IDENT_START.match(data, i):
            start = i
            kind = IDENT.match(data, i).group(0).decode()
            i = IDENT.match(data, i).end()
            labels: list[str] = []
            while i < n:
                while i < n and data[i : i + 1] in (b" ", b"\t"):
                    i += 1
                c = data[i : i + 1]
                if c == b'"':
                    j = _skip_string(data, i)
                    labels.append(data[i + 1 : j - 1].decode())
                    i = j
                elif IDENT_START.match(data, i):
                    m = IDENT.match(data, i)
                    labels.append(m.group(0).decode())
                    i = m.end()
                else:
                    break
            if data[i : i + 1] == b"{":
                end = _find_block_end(data, i)
                blocks.append(
                    Block(path, kind, tuple(labels), start, end, i + 1, end - 1,
                          data.count(b"\n", 0, start) + 1)
                )
                i = end
            else:  # top-level attribute or junk: skip the line
                i = _skip_line(data, i)
        else:
            i += 1
    return blocks


@dataclass
class Index:
    blocks: dict[str, Block]
    duplicates: dict[str, list[Block]]
    errors: dict[Path, str]


def index_dir(tf_dir: Path) -> Index:
    """Map resource addresses across every *.tf in tf_dir (non-recursive, like Terraform)."""
    idx = Index({}, {}, {})
    for p in sorted(Path(tf_dir).glob("*.tf")):
        try:
            found = scan_blocks(p.read_bytes(), p)
        except ScanError as e:
            idx.errors[p] = str(e)
            continue
        for b in found:
            if b.kind != "resource":
                continue
            if b.address in idx.blocks:
                idx.duplicates.setdefault(b.address, [idx.blocks[b.address]]).append(b)
            else:
                idx.blocks[b.address] = b
    return idx


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="List resource addresses across a Terraform dir")
    ap.add_argument("--tf-dir", required=True, type=Path)
    a = ap.parse_args()
    idx = index_dir(a.tf_dir)
    for addr, b in sorted(idx.blocks.items()):
        print(f"{addr}\t{b.path.name}:{b.line}\tbytes {b.start}-{b.end}")
    for addr, bl in idx.duplicates.items():
        print(f"DUPLICATE {addr}: " + ", ".join(f"{b.path.name}:{b.line}" for b in bl))
    for p, e in idx.errors.items():
        print(f"ERROR {p.name}: {e}")
    return 1 if idx.duplicates or idx.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
