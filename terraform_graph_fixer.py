#!/usr/bin/env python3
"""terraform_graph_fixer: multi-file, format-preserving Terraform scanner/indexer.

Stage 1 (this file so far): Scanner + Indexer.
All offsets are BYTE offsets into the original file contents.
"""
from __future__ import annotations

import difflib
import fnmatch
import functools
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
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


# ======================================================================
# Stage 2: edit engine, fixers, classifier, transaction
# ======================================================================

SSE_TYPE = "aws_s3_bucket_server_side_encryption_configuration"
G1_PRIMITIVES = ("ec2:runinstances", "lambda:createfunction", "ecs:registertaskdefinition")


# ---------------- edits ----------------
@dataclass(frozen=True)
class Edit:
    path: Path
    start: int
    end: int  # start == end means pure insert
    text: str


class EditError(Exception):
    """Overlapping or out-of-range edits. Raised BEFORE any file is touched."""


def apply_edits_to_bytes(data: bytes, edits: list[Edit]) -> bytes:
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    for e in ordered:
        if not 0 <= e.start <= e.end <= len(data):
            raise EditError(f"edit out of range in {e.path}: {e.start}-{e.end} (size {len(data)})")
    for a, b in zip(ordered, ordered[1:]):
        if b.start < a.end or b.start == a.start:
            raise EditError(f"overlapping edits in {a.path}: {a.start}-{a.end} and {b.start}-{b.end}")
    out = data
    for e in reversed(ordered):  # descending offsets keep earlier offsets valid
        out = out[: e.start] + e.text.encode() + out[e.end :]
    return out


def merge_inserts(edits: list[Edit]) -> list[Edit]:
    """Several pure inserts at the same offset become one edit (deterministic order)."""
    merged: dict[tuple[Path, int], list[str]] = {}
    rest: list[Edit] = []
    for e in edits:
        if e.start == e.end:
            merged.setdefault((e.path, e.start), []).append(e.text)
        else:
            rest.append(e)
    for (path, pos), texts in merged.items():
        rest.append(Edit(path, pos, pos, "".join(texts)))
    return rest


def compute_new_contents(edits: list[Edit]) -> dict[Path, bytes]:
    by_path: dict[Path, list[Edit]] = {}
    for e in merge_inserts(edits):
        by_path.setdefault(e.path, []).append(e)
    out = {}
    for p, es in by_path.items():
        data = p.read_bytes() if p.exists() else b""
        out[p] = apply_edits_to_bytes(data, es)
    return out


def _atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path = Path(path)
    if mode is None:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------- comment masking ----------------
def mask_comments(data: bytes) -> bytes:
    """Same length as data, with comment text blanked (strings/heredocs untouched)."""
    out = bytearray(data)
    i, n = 0, len(data)
    while i < n:
        c = data[i : i + 1]
        if c == b'"':
            i = _skip_string(data, i)
        elif c == b"#" or data[i : i + 2] == b"//":
            j = _skip_line(data, i)
            out[i:j] = b" " * (j - i)
            i = j
        elif data[i : i + 2] == b"/*":
            j = _skip_block_comment(data, i)
            for k in range(i, j):
                if data[k] not in (10, 13):
                    out[k] = 32
            i = j
        elif data[i : i + 2] == b"<<":
            end = _skip_heredoc(data, i)
            i = end if end is not None else i + 2
        else:
            i += 1
    return bytes(out)


# ---------------- findings ----------------
@dataclass
class Finding:
    rule: str
    address: str
    file: str
    line: int
    cls: str  # AUTO | MANUAL
    guidance: str
    edits: list[Edit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "address": self.address, "file": self.file,
                "line": self.line, "class": self.cls, "action_or_guidance": self.guidance}


COUNT_RE = re.compile(rb"(?m)^\s*(count|for_each)\s*=")


def _ref_re(addr: str) -> re.Pattern:
    return re.compile(rb"(?<![A-Za-z0-9_.-])" + re.escape(addr.encode()) + rb"(?![A-Za-z0-9_-])")


def _eol(data: bytes) -> str:
    return "\r\n" if b"\r\n" in data else "\n"


def find_s3_sse(idx: Index, raw: dict[Path, bytes], masked: dict[Path, bytes]) -> list[Finding]:
    """G2 (fixer side): bucket with no SSE companion anywhere in the directory."""
    companions = [b for b in idx.blocks.values() if b.labels[0] == SSE_TYPE]
    findings: list[Finding] = []
    for addr, b in sorted(idx.blocks.items()):
        if b.labels[0] != "aws_s3_bucket":
            continue
        name = b.labels[1]
        ref = _ref_re(addr)
        if any(ref.search(masked[c.path][c.body_start : c.body_end]) for c in companions):
            continue
        where = dict(rule="G2-s3-sse", address=addr, file=b.path.name, line=b.line)
        if COUNT_RE.search(masked[b.path][b.body_start : b.body_end]):
            findings.append(Finding(cls="MANUAL", guidance=(
                "Bucket uses count/for_each; add a companion with matching count/for_each "
                f"referencing {addr}[each.key] (or [count.index]) by hand."), **where))
            continue
        cname = name
        if f"{SSE_TYPE}.{cname}" in idx.blocks:
            cname = f"{name}_sse"
        if f"{SSE_TYPE}.{cname}" in idx.blocks:
            findings.append(Finding(cls="MANUAL", guidance=(
                f"Name {SSE_TYPE}.{name} and {name}_sse are both taken; "
                "add a companion with a unique name."), **where))
            continue
        eol = _eol(raw[b.path])
        lines = [
            f'resource "{SSE_TYPE}" "{cname}" {{',
            f"  bucket = {addr}.id",
            "",
            "  rule {",
            "    apply_server_side_encryption_by_default {",
            '      sse_algorithm = "AES256"',
            "    }",
            "  }",
            "}",
        ]
        text = eol.join(lines) + eol
        data = raw[b.path]
        prefix = "" if data.endswith(b"\n") or not data else eol
        pos = len(data)
        sep = eol if data else ""
        findings.append(Finding(
            cls="AUTO",
            guidance=f"Append {SSE_TYPE}.{cname} (AES256) referencing {addr}.id",
            edits=[Edit(b.path, pos, pos, prefix + sep + text)], **where))
    return findings


ACTION_VALUE_RE = re.compile(rb'\bAction"?\s*[=:]\s*(\[[^\]]*\]|"[^"]*")')
STRING_RE = re.compile(rb'"([^"]+)"')
ROLE_RE = re.compile(rb"\brole\s*=\s*aws_iam_role\.([A-Za-z0-9_-]+)")


def find_g1_manual(idx: Index, masked: dict[Path, bytes]) -> list[Finding]:
    """G1 is NEVER auto-patched. Text-level heuristic; the Rego rule is authoritative."""
    per_role: dict[str, set[str]] = {}
    first_block: dict[str, Block] = {}
    for b in idx.blocks.values():
        if b.labels[0] != "aws_iam_role_policy":
            continue
        body = masked[b.path][b.body_start : b.body_end]
        m = ROLE_RE.search(body)
        if not m:
            continue
        role = m.group(1).decode()
        acts = per_role.setdefault(role, set())
        for m in ACTION_VALUE_RE.finditer(body):  # Action values only, never Resource
            acts.update(a.decode().lower() for a in STRING_RE.findall(m.group(1)))
        first_block.setdefault(role, b)
    findings = []
    for role, actions in sorted(per_role.items()):
        passes = any(fnmatch.fnmatchcase("iam:passrole", a) for a in actions)
        prims = [p for p in G1_PRIMITIVES if any(fnmatch.fnmatchcase(p, a) for a in actions)]
        if passes and prims:
            rb = idx.blocks.get(f"aws_iam_role.{role}") or first_block[role]
            findings.append(Finding(
                rule="G1-privesc-pair", address=f"aws_iam_role.{role}",
                file=rb.path.name, line=rb.line, cls="MANUAL",
                guidance=(
                    "Role can iam:PassRole and create compute (" + ", ".join(prims) + "). "
                    "Scope iam:PassRole Resource to specific role ARNs, add an "
                    "iam:PassedToService condition, and split the creation permission "
                    "into a separate role. Not auto-fixed: the right scope depends on "
                    "which role and service need it.")))
    return findings


# ---------------- open-egress fixer (G3) ----------------
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
DEFAULT_PROFILE = (("tcp", 443),)


def parse_profile(text: str) -> tuple[tuple[str, int], ...]:
    """'tcp/443,udp/53' -> (('tcp', 443), ('udp', 53)). The allowlist is an explicit policy choice."""
    out: list[tuple[str, int]] = []
    for part in text.split(","):
        proto, _, port = part.strip().partition("/")
        if proto not in ("tcp", "udp") or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f"bad egress profile entry {part!r}; use e.g. tcp/443 or udp/53")
        if (proto, int(port)) not in out:
            out.append((proto, int(port)))
    return tuple(out)


def _attr_re(key: str) -> re.Pattern:
    return re.compile(rb"(?m)^([ \t]*)" + re.escape(key.encode()) + rb"([ \t]*)=([ \t]*)([^\r\n]*)")


def _literal(masked: bytes, key: str) -> str | None:
    m = _attr_re(key).search(masked)
    return m.group(4).rstrip().decode() if m else None


def _str(val: str | None) -> str | None:
    m = re.fullmatch(r'"([^"]*)"', val or "")
    return m.group(1) if m else None


def _int(val: str | None) -> int | None:
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def _str_list(val: str | None) -> list[str] | None:
    """Literal one-line list of strings, else None (variables, multi-line lists, ...)."""
    m = re.fullmatch(r"\[(.*)\]", (val or "").strip())
    if not m or re.sub(r'"[^"]*"|[\s,]', "", m.group(1)):
        return None
    return re.findall(r'"([^"]*)"', m.group(1))


def _full_range(masked: bytes) -> bool:
    return _int(_literal(masked, "from_port")) == 0 and _int(_literal(masked, "to_port")) == 65535


def _verdict_sg_like(masked: bytes) -> str | None:
    """'auto' | 'manual:<why>' | None (not provably open) for inline egress / aws_security_group_rule."""
    v4, v6 = _literal(masked, "cidr_blocks"), _literal(masked, "ipv6_cidr_blocks")
    l4, l6 = _str_list(v4), _str_list(v6)
    if (v4 is not None and l4 is None) or (v6 is not None and l6 is None):
        return None  # not statically resolvable: the plan-time Rego rule decides
    cidrs = (l4 or []) + (l6 or [])
    if not any(c in OPEN_CIDRS for c in cidrs):
        return None
    proto = _str(_literal(masked, "protocol"))
    if not (proto in ("-1", "all") or _full_range(masked)):
        return None
    if any(c not in OPEN_CIDRS for c in cidrs):
        return "manual:cidr list mixes open and private ranges; tightening would change the private ones"
    for k in ("security_groups", "prefix_list_ids", "self"):
        if _attr_re(k).search(masked):
            return f"manual:rule also targets {k}; tightening would change those destinations"
    return "auto"


def _verdict_vpc(masked: bytes) -> str | None:
    c4, c6 = _str(_literal(masked, "cidr_ipv4")), _str(_literal(masked, "cidr_ipv6"))
    if not (c4 in OPEN_CIDRS or c6 in OPEN_CIDRS):
        return None
    proto = _str(_literal(masked, "ip_protocol"))
    return "auto" if (proto in ("-1", "all") or _full_range(masked)) else None


def _render(text: bytes, masked: bytes, sets: dict[str, str], anchor: str) -> bytes | None:
    """Set attribute values (inserting missing ones after `anchor`, aligned for terraform fmt)."""
    eol = _eol(text)
    edits: list[Edit] = []
    inserts: list[tuple[str, str]] = []
    for key, val in sets.items():
        m = _attr_re(key).search(masked)
        if m:
            start = m.start(4)
            edits.append(Edit(Path("<block>"), start, start + len(m.group(4).rstrip()), val))
        else:
            inserts.append((key, val))
    if inserts:
        am = _attr_re(anchor).search(masked)
        nl = text.find(b"\n", am.end()) if am else -1
        if not am or nl == -1:
            return None
        indent = am.group(1).decode()
        eq_col = len(indent) + len(anchor) + len(am.group(2))
        lines = []
        for k, v in inserts:
            pad = eq_col - len(indent) - len(k)
            if pad < 1:
                return None
            lines.append(f"{indent}{k}{' ' * pad}= {v}")
        edits.append(Edit(Path("<block>"), nl + 1, nl + 1, eol.join(lines) + eol))
    return apply_edits_to_bytes(text, edits)


def _rename_resource(text: bytes, old: str, new: str) -> bytes | None:
    pat = re.compile(rb'^(resource\s+"[^"]+"\s+)"' + re.escape(old.encode()) + rb'"')
    out, n = pat.subn(lambda m: m.group(1) + b'"' + new.encode() + b'"', text, count=1)
    return out if n else None


def _profile_text(profile) -> str:
    return ", ".join(f"{p}/{n}" for p, n in profile)


def find_open_egress(idx: Index, raw: dict[Path, bytes], masked: dict[Path, bytes],
                     profile=DEFAULT_PROFILE) -> list[Finding]:
    findings: list[Finding] = []
    for addr, b in sorted(idx.blocks.items()):
        kind = b.labels[0]
        r, m = raw[b.path], masked[b.path]
        eol = _eol(r)
        if kind == "aws_security_group":
            inner = m[b.body_start : b.body_end]
            for nb in scan_blocks(inner):
                if nb.kind != "egress":
                    continue
                s, e = b.body_start + nb.start, b.body_start + nb.end
                verdict = _verdict_sg_like(m[s:e])
                if verdict is None:
                    continue
                line = r.count(b"\n", 0, s) + 1
                where = dict(rule="G3-open-egress", address=addr, file=b.path.name, line=line)
                ls = r.rfind(b"\n", 0, s) + 1
                indent = r[ls:s]
                if verdict != "auto" or indent.strip():
                    why = verdict[7:] if verdict != "auto" else "egress block is not alone on its line"
                    findings.append(Finding(cls="MANUAL", guidance=f"Open egress block: {why}.", **where))
                    continue
                copies = []
                for proto, port in profile:
                    copies.append(_render(r[s:e], m[s:e], {
                        "protocol": f'"{proto}"', "from_port": str(port), "to_port": str(port)},
                        "protocol"))
                if any(c is None for c in copies):
                    findings.append(Finding(cls="MANUAL", guidance="Could not rewrite egress block safely.", **where))
                    continue
                text = (eol.encode() + indent).join(copies).decode()
                findings.append(Finding(
                    cls="AUTO", guidance=f"Restrict open egress block to {_profile_text(profile)}",
                    edits=[Edit(b.path, s, e, text)], **where))
        elif kind in ("aws_security_group_rule", "aws_vpc_security_group_egress_rule"):
            text_m = m[b.start : b.end]
            vpc = kind == "aws_vpc_security_group_egress_rule"
            if not vpc and _str(_literal(text_m, "type")) != "egress":
                continue
            verdict = _verdict_vpc(text_m) if vpc else _verdict_sg_like(text_m)
            if verdict is None:
                continue
            where = dict(rule="G3-open-egress", address=addr, file=b.path.name, line=b.line)
            if COUNT_RE.search(text_m):
                findings.append(Finding(cls="MANUAL", guidance=(
                    "Open egress rule uses count/for_each; restrict it by hand."), **where))
                continue
            if verdict != "auto":
                findings.append(Finding(cls="MANUAL", guidance=f"Open egress rule: {verdict[7:]}.", **where))
                continue
            pk = "ip_protocol" if vpc else "protocol"
            name = b.labels[1]
            copies, clash = [], None
            for i, (proto, port) in enumerate(profile):
                body = _render(r[b.start : b.end], text_m, {
                    pk: f'"{proto}"', "from_port": str(port), "to_port": str(port)}, pk)
                if body is not None and i > 0:
                    new = f"{name}_{proto}_{port}"
                    if f"{kind}.{new}" in idx.blocks:
                        clash = new
                    body = _rename_resource(body, name, new)
                if body is None:
                    copies = None
                    break
                copies.append(body)
            if clash or copies is None:
                findings.append(Finding(cls="MANUAL", guidance=(
                    "Could not generate restricted copies safely"
                    + (f" (name {clash} already exists)" if clash else "") + "."), **where))
                continue
            text = (eol.encode() * 2).join(copies).decode()
            findings.append(Finding(
                cls="AUTO", guidance=f"Restrict open egress rule to {_profile_text(profile)}",
                edits=[Edit(b.path, b.start, b.end, text)], **where))
    return findings


def plan_fixes(tf_dir: Path, profile=DEFAULT_PROFILE) -> tuple[Index, list[Finding]]:
    idx = index_dir(tf_dir)
    files = {p for b in idx.blocks.values() for p in [b.path]}
    raw = {p: p.read_bytes() for p in files}
    masked = {p: mask_comments(d) for p, d in raw.items()}
    findings = (find_s3_sse(idx, raw, masked) + find_open_egress(idx, raw, masked, profile)
                + find_g1_manual(idx, masked))
    return idx, findings


# ---------------- checks and transaction ----------------
@dataclass
class CheckResult:
    name: str
    status: str  # PASS | FAIL | SKIPPED
    detail: str = ""


class CheckFailed(Exception):
    def __init__(self, results: list[CheckResult]):
        self.results = results
        bad = [r for r in results if r.status == "FAIL"]
        super().__init__("check failed: " + ", ".join(r.name for r in bad))


def run_checks(tf_dir: Path, tflint_config: Path | None = None) -> list[CheckResult]:
    tf = shutil.which("terraform")
    if not tf:
        return [CheckResult("terraform", "FAIL", "terraform not found on PATH (fail closed)")]
    results: list[CheckResult] = []
    steps = [
        ("fmt", [tf, "fmt", "-check", "-recursive"]),
        ("init", [tf, "init", "-backend=false", "-input=false"]),
        ("validate", [tf, "validate"]),
    ]
    for name, cmd in steps:
        r = subprocess.run(cmd, cwd=tf_dir, capture_output=True, text=True)
        status = "PASS" if r.returncode == 0 else "FAIL"
        results.append(CheckResult(name, status, (r.stdout + r.stderr).strip()[-2000:]))
        if status == "FAIL":
            return results
    tl = shutil.which("tflint")
    if not tl:
        results.append(CheckResult("tflint", "SKIPPED", "tflint not installed"))
    else:
        cmd = [tl, f"--chdir={tf_dir}"]
        if tflint_config:  # --chdir only auto-discovers a config inside the target dir
            cmd.append(f"--config={Path(tflint_config).resolve()}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append(CheckResult("tflint", "PASS" if r.returncode == 0 else "FAIL",
                                   (r.stdout + r.stderr).strip()[-2000:]))
    return results


def _snapshot(tf_dir: Path, touched) -> tuple[dict, set]:
    paths = set(tf_dir.glob("*.tf")) | {tf_dir / ".terraform.lock.hcl"} | set(touched)
    snap = {p: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in paths if p.exists()}
    return snap, paths


def _restore(snap: dict, paths: set) -> None:
    for p in paths:
        if p in snap:
            data, mode = snap[p]
            if not p.exists() or p.read_bytes() != data:
                _atomic_write(p, data, mode)
            elif stat.S_IMODE(p.stat().st_mode) != mode:
                os.chmod(p, mode)
        elif p.exists():
            p.unlink()  # file created by this transaction


def apply_transaction(edits: list[Edit], tf_dir: Path, checks=run_checks) -> list[CheckResult]:
    tf_dir = Path(tf_dir)
    new = compute_new_contents(edits)  # EditError here means nothing was touched
    snap, paths = _snapshot(tf_dir, new.keys())
    try:
        for p, data in sorted(new.items()):
            _atomic_write(p, data)
        results = checks(tf_dir)
        if any(r.status == "FAIL" for r in results):
            raise CheckFailed(results)
        return results
    except BaseException:
        _restore(snap, paths)
        raise


def render_diff(edits: list[Edit]) -> str:
    chunks = []
    for p, new in sorted(compute_new_contents(edits).items()):
        old = p.read_bytes() if p.exists() else b""
        chunks.extend(difflib.unified_diff(
            old.decode().splitlines(keepends=True), new.decode().splitlines(keepends=True),
            fromfile=f"a/{p.name}", tofile=f"b/{p.name}"))
    return "".join(chunks)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Multi-file Terraform graph fixer")
    ap.add_argument("--tf-dir", required=True, type=Path)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="show diff only (default)")
    mode.add_argument("--apply", action="store_true", help="apply fixes transactionally")
    ap.add_argument("--index", action="store_true", help="list resource addresses and exit")
    ap.add_argument("--report", type=Path, help="write JSON report here")
    ap.add_argument("--egress-profile", default="tcp/443",
                    help="allowlist replacing open egress, e.g. tcp/443,udp/53 (default tcp/443)")
    ap.add_argument("--tflint-config", type=Path,
                    help="tflint config (default: ./.tflint.hcl when present)")
    a = ap.parse_args(argv)

    idx = index_dir(a.tf_dir)
    if a.index:
        for addr, b in sorted(idx.blocks.items()):
            print(f"{addr}\t{b.path.name}:{b.line}\tbytes {b.start}-{b.end}")
    if idx.duplicates or idx.errors:
        for addr, bl in idx.duplicates.items():
            print(f"REFUSED duplicate {addr}: " + ", ".join(f"{b.path.name}:{b.line}" for b in bl))
        for p, e in idx.errors.items():
            print(f"REFUSED parse error {p.name}: {e}")
        return 2
    if a.index:
        return 0

    try:
        profile = parse_profile(a.egress_profile)
    except ValueError as e:
        print(f"REFUSED {e}")
        return 2
    _, findings = plan_fixes(a.tf_dir, profile)
    edits = [e for f in findings if f.cls == "AUTO" for e in f.edits]
    report = {"findings": [f.to_dict() for f in findings], "applied": False, "checks": []}
    for f in findings:
        print(f"[{f.cls}] {f.rule} {f.address} ({f.file}:{f.line}): {f.guidance}")
    rc = 0
    if edits:
        print("\n" + render_diff(edits))
        if a.apply:
            try:
                cfg = a.tflint_config or (Path(".tflint.hcl") if Path(".tflint.hcl").exists() else None)
                results = apply_transaction(
                    edits, a.tf_dir, checks=functools.partial(run_checks, tflint_config=cfg))
                report["applied"] = True
                report["checks"] = [r.__dict__ for r in results]
            except CheckFailed as e:
                report["checks"] = [r.__dict__ for r in e.results]
                print(f"ROLLED BACK: {e}")
                rc = 1
    if a.report:
        a.report.write_text(json.dumps(report, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
