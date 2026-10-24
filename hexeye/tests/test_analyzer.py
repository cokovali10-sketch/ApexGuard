import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from hexeye.analyzer import (
    HexEyeReport,
    analyze,
    detect_format,
    find_sections,
    find_text_section_elf64,
    parse_elf_header,
    risk_label,
    risk_score,
    scan_secrets,
)
# --- константы вынесены FORGE refactor ---
CONST_64 = 64



def _build_elf() -> bytes:
    """Собираем настоящий ELF64 (используем доступный Go-компилятор)."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "go.mod").write_text("module sample\n\ngo 1.21\n")
        (d / "main.go").write_text(
            'package main\nfunc main() { println("hi") }\n'
        )
        out = d / "a.out"
        r = subprocess.run(["go", "build", "-o", str(out), "."], cwd=d, capture_output=True)
        if r.returncode != 0:
            pytest.skip(f"cannot build sample ELF: {r.stderr.decode()[:200]}")
        data = out.read_bytes()
        if not data.startswith(b"\x7fELF"):
            pytest.skip("go produced a non-ELF binary (need linux cross?)")
        return data


def test_detect_format():
    assert detect_format(b"\x7fELF\x02\x01\x01") == "elf"
    assert detect_format(b"\x7fELF\x01\x01\x01") == "elf"
    assert detect_format(b"MZ\x90\x00") == "pe"
    assert detect_format(b"\xca\xfe\xba\xbe") is None


def _elf64_header() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    h = ident + struct.pack("<HH", 2, 0x3E)   # e_type=EXEC, e_machine=x86_64
    h += struct.pack("<I", 1)                 # e_version
    h += struct.pack("<Q", 0x401000)          # e_entry
    return h.ljust(CONST_64, b"\x00")


def test_parse_elf_header():
    h = parse_elf_header(_elf64_header())
    assert h["class"] == "ELF64"
    assert h["machine"] == "x86_64"
    assert h["entry"] == "0x401000"
    assert h["type"] == "EXEC"


def test_find_text_section_real_elf():
    elf = _build_elf()
    if not elf:
        return
    off, size = find_text_section_elf64(elf)
    assert off is not None and size > 0
    # .text не может начинаться с нулевого байта эфира — это наш сектор
    assert elf[off:off + 4] not in (b"\x00\x00\x00\x00",)


def test_find_sections_real_elf():
    elf = _build_elf()
    if not elf:
        return
    secs = find_sections(elf)
    names = {s["name"] for s in secs}
    assert ".text" in names
    text = next(s for s in secs if s["name"] == ".text")
    assert text["size"] > 0


def test_scan_secrets():
    blob = b"x" * CONST_64 + b"AKIAIOSFODNN7EXAMPLE" + b"y" * CONST_64
    hits = scan_secrets(blob)
    types = {h["type"] for h in hits}
    assert "AWS_ACCESS_KEY" in types

    blob2 = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"z" * 128 + b"\n-----END OPENSSH PRIVATE KEY-----"
    hits2 = scan_secrets(blob2)
    assert "RSA_PRIVATE" in {h["type"] for h in hits2}


def test_analyze_runs_and_scores():
    elf = _build_elf()
    if not elf:
        return
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bin"
        p.write_bytes(elf)
        r = analyze(str(p))
    assert isinstance(r, HexEyeReport)
    assert r.format == "elf"
    assert 0.0 <= r.risk_score <= 1.0


def test_risk_label_buckets():
    assert risk_label(0.1) == "low"
    assert risk_label(0.4) == "medium"
    assert risk_label(0.5) == "high"
    assert risk_label(0.75) == "critical"
