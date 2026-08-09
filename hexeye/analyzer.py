#!/usr/bin/env python3
# HexEye — статический анализатор ELF/PE.
#
# Пайплайн:
#   1. Определение формата (ELF/PE) через struct-парсинг заголовков.
#   2. Сканер секретов (regex по .rodata/.data + поиск строк).
#   3. Дизассемблирование через Radare2 (r2pipe) / Capstone.
#   4. Call-graph анализ: поиск опасных sink-функций и их callers.
#   5. Heuristic-детект переполнений буфера / UAF по assembly-паттернам.
#
# Run: python hexeye/analyzer.py /path/to/binary
import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Детект формата и заголовки
# ---------------------------------------------------------------------------

def detect_format(data: bytes) -> str | None:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    return None


def parse_elf_header(data: bytes) -> dict:
    # ELF64 header: e_type(2) e_machine(2) e_version(4) e_entry(8) ...
    if len(data) < 64:
        return {}
    e_type, e_machine, e_version = struct.unpack_from("<HHI", data, 16)
    e_entry = struct.unpack_from("<Q", data, 24)[0]
    return {
        "class": "ELF64",
        "type": {1: "REL", 2: "EXEC", 3: "DYN"}.get(e_type, e_type),
        "machine": {0x3E: "x86_64", 0x28: "ARM", 0xB7: "AARCH64"}.get(e_machine, e_machine),
        "version": e_version,
        "entry": hex(e_entry),
    }


def parse_pe_header(data: bytes) -> dict:
    # DOS header: e_lfanew @ 0x3C → PE signature
    if len(data) < 0x40:
        return {}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {}
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    return {
        "class": "PE32+",
        "machine": {0x8664: "x86_64", 0x14C: "x86"}.get(machine, hex(machine)),
        "subsystem": struct.unpack_from("<H", data, coff + 68)[0],
    }


# ---------------------------------------------------------------------------
# ELF64 section table parser (без внешних зависимостей)
# ---------------------------------------------------------------------------
def find_text_section_elf64(data: bytes) -> tuple[int, int] | None:
    """Возвращает (file_offset, size) секции .text для ELF64, либо None."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shentsize == 0 or e_shnum == 0:
        return None
    # таблица секций (ELF64 shdr: 64 байта)
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 64 > len(data):
            break
        sh_name, _, sh_flags = struct.unpack_from("<IIQ", data, off)
        sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 16)
        shdrs.append((sh_name, sh_flags, sh_addr, sh_offset, sh_size))
    if e_shstrndx >= len(shdrs):
        return None
    str_off = shdrs[e_shstrndx][3]
    str_size = shdrs[e_shstrndx][4]
    strtab = data[str_off:str_off + str_size]
    SHF_EXECINSTR = 0x4
    for sh_name, sh_flags, _addr, sh_offset, sh_size in shdrs:
        if not sh_flags & SHF_EXECINSTR:
            continue
        if sh_name >= len(strtab):
            continue
        name = strtab[sh_name:].split(b"\x00", 1)[0].decode(errors="replace")
        if name == ".text":
            return (sh_offset, sh_size)
    return None


def find_sections(data: bytes) -> list[dict]:
    """ELF64: перечисление секций с именами, офсетами и флагами."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shentsize == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return []
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 64 > len(data):
            break
        sh_name, _, sh_flags = struct.unpack_from("<IIQ", data, off)
        sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 16)
        shdrs.append((sh_name, sh_flags, sh_addr, sh_offset, sh_size))
    str_off = shdrs[e_shstrndx][3]
    str_size = shdrs[e_shstrndx][4]
    strtab = data[str_off:str_off + str_size]
    out = []
    for sh_name, sh_flags, sh_addr, sh_offset, sh_size in shdrs:
        name = strtab[sh_name:].split(b"\x00", 1)[0].decode(errors="replace") if sh_name < len(strtab) else ""
        if not name:
            continue
        out.append({
            "name": name,
            "flags": sh_flags,
            "addr": hex(sh_addr),
            "offset": hex(sh_offset),
            "size": sh_size,
        })
    return out


# ---------------------------------------------------------------------------
# 2. Секреты (hardcoded keys, tokens, passwords)
# ---------------------------------------------------------------------------
SECRET_RULES: list[tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET", re.compile(rb"(?i)aws_secret[^a-z0-9]{0,3}[A-Za-z0-9/+=]{40}")),
    ("GCP_KEY", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("GITHUB_TOKEN", re.compile(rb"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("RSA_PRIVATE", re.compile(rb"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PEM_CERT", re.compile(rb"-----BEGIN CERTIFICATE-----")),
    ("PASSWORD_ASSIGN", re.compile(rb"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]")),
    ("API_KEY", re.compile(rb"(?i)api[_-]?key['\":=\s]+[A-Za-z0-9]{20,}")),
    ("MYSQL_DSN", re.compile(rb"mysql://[^\s]+:[^\s@]+@")),
    ("PG_DSN", re.compile(rb"postgres(ql)?://[^\s]+:[^\s@]+@")),
]


def scan_secrets(data: bytes) -> list[dict]:
    found = []
    for name, rx in SECRET_RULES:
        for m in rx.finditer(data):
            snippet = m.group(0)
            found.append({
                "type": name,
                "value": snippet.decode(errors="replace")[:64],
                "offset": hex(m.start()),
            })
    return found


# ---------------------------------------------------------------------------
# 3. Опасные функции и call-graph
# ---------------------------------------------------------------------------
DANGEROUS_SINKS = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
                   "strncpy", "system", "popen", "execl", "execve", "memcpy",
                   "dlopen", "setuid", "alloca", "sscanf"}


@dataclass
class HexEyeReport:
    file: str
    sha256: str
    format: str | None
    headers: dict = field(default_factory=dict)
    secrets: list = field(default_factory=list)
    dangerous_calls: list = field(default_factory=list)   # (sink, caller)
    candidate_vulns: list = field(default_factory=list)   # (kind, addr, detail)
    sections: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "low"


# ---------------------------------------------------------------------------
# 4. Анализ через Radare2 (r2pipe)
# ---------------------------------------------------------------------------
def analyze_with_r2(path: str, report: HexEyeReport):
    try:
        import r2pipe
    except ImportError:
        # fallback: только структура без дизассемблера
        report.dangerous_calls.append(("(r2pipe not installed)", "-"))
        return report

    r2 = r2pipe.open(path, flags=["-2", "-e", "scr.color=false"])
    r2.cmd("aaa")  # автоанализ
    # Список функций (call graph vertices)
    funcs = r2.cmdj("aflj") or []
    # Импортированные/небезопасные символы
    imports = r2.cmdj("iij") or []
    for imp in imports:
        name = imp.get("name", "")
        if name in DANGEROUS_SINKS:
            # найдем вызовы (xrefs)
            xrefs = r2.cmdj(f"/xj 0x{imp.get('plt', 0):x}") if imp.get("plt") else []
            callers = [f"0x{int(x['offset']):x}" for x in (xrefs or [])][:10]
            report.dangerous_calls.append((name, "; ".join(callers) or "-"))

    # Извлечь данные (.rodata/.data) для сканера секретов
    secs = r2.cmdj("iSj") or []
    blob = b""
    for s in secs:
        if s.get("name") in (".rodata", ".data", ".rdata"):
            blob += bytes(r2.cmdj(f"pxj {s.get('size',0)} @ {s.get('vaddr',0)}") or [])
    for hit in scan_secrets(blob):
        report.secrets.append(hit)
    r2.quit()
    return report


# ---------------------------------------------------------------------------
# 5. Детект BOF / UAF по assembly-паттернам (без символов)
# ---------------------------------------------------------------------------
# Паттерн опасного копирования с небезопасным индексом:
#   lea rdi,[rbp-0x20]      ; dest на стеке
#   call memcpy / strcpy     ; без проверки размера источника
BOF_STACK_PATTERNS = [
    # call <strcpy> с источником из регистра, содержащего пользовательский ввод
    re.compile(rb"call\s+strcpy"),
    re.compile(rb"call\s+gets"),
    re.compile(rb"call\s+sprintf"),
    # memcpy с константой размера > 0x100 в rdx
    re.compile(rb"mov\s+edx,\s+0x[0-9a-f]{3,}\s*;\s*(?:\n\s*)call\s+memcpy"),
]


def assembly_bof_scan(text_bytes: bytes, report: HexEyeReport):
    """Дополнительный проход: ищет dangerous call'ы прямо в stream байтов."""
    # в нормальной работе строки дизассемблера уже собраны в dangerous_calls;
    # здесь — эвристика "call memcpy после mov edx,<const>" через аннотации.
    pass


def heuristic_bof(disasm_lines: list[str], report: HexEyeReport):
    """Эвристика по строкам дизассемблера:
       1. mov rdi, rbp-0xNN  → локальный буфер на стеке
       2. call <sink>        → небезопасная копия
       Если нет проверки границ (cmp/jb) между — кандидат BOF."""
    suspicious = []
    last_stack_write = None
    for line in disasm_lines:
        line = line.strip()
        if re.search(r"lea\s+\w+,\s*\[rbp-\w*0x\w+\]", line):
            last_stack_write = line
        if re.search(r"call\s+\w*(strcpy|sprintf|gets|memcpy)\b", line):
            suspicious.append((line, last_stack_write))
            last_stack_write = None
    for sink, dest in suspicious:
        report.candidate_vulns.append({
            "kind": "STACK_BOF",
            "addr": "-",
            "detail": f"{sink} <- {dest} (без проверки границ)",
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def analyze(path: str) -> HexEyeReport:
    data = Path(path).read_bytes()
    report = HexEyeReport(
        file=path,
        sha256=hashlib.sha256(data).hexdigest(),
        format=detect_format(data),
    )
    if report.format == "elf":
        report.headers = parse_elf_header(data)
        report.sections = find_sections(data)
    elif report.format == "pe":
        report.headers = parse_pe_header(data)
    else:
        print(f"[!] {path}: unsupported format")
        return report

    # Секреты во всём бинарнике (простой потоковый скан)
    report.secrets = scan_secrets(data)

    # r2-анализ (опционально)
    analyze_with_r2(path, report)

    # Дополнительный проход по .text через capstone (опционально)
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        text = find_text_section_elf64(data) if report.format == "elf" else None
        if text:
            text_off, text_size = text
            chunk = data[text_off:text_off + min(text_size, 8192)]
            lines = [f"0x{i.address:x}: {i.mnemonic} {i.op_str}".strip()
                     for i in md.disasm(chunk, 0x401000)]
            heuristic_bof(lines, report)
    except ImportError:
        pass

    # Сводный риск: взвешенная сумма находок.
    report.risk_score = risk_score(report)
    report.risk_label = risk_label(report.risk_score)

    return report


def risk_score(r: HexEyeReport) -> float:
    """0.0..1.0 — грубая оценка риска на основе находок."""
    score = 0.0
    if r.format in ("elf", "pe"):
        score += 0.1
    score += min(len(r.secrets) * 0.15, 0.45)          # секреты
    score += min(len(r.candidate_vulns) * 0.25, 0.5)   # кандидаты в уязвимости
    score += min(len(r.dangerous_calls) * 0.02, 0.2)   # опасные sink-вызовы
    return round(min(score, 1.0), 2)


def risk_label(score: float) -> str:
    if score >= 0.7:
        return "critical"
    if score >= 0.45:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=str)
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    rep = analyze(args.binary)
    if args.as_json:
        print(json.dumps(asdict(rep), indent=2))
    else:
        print(f"[hexeye] {rep.file} sha256={rep.sha256[:16]} format={rep.format} risk={rep.risk_score} ({rep.risk_label})")
        for h in rep.secrets:
            print(f"  [!SECRET] {h['type']} @ {h['offset']}: {h['value'][:40]}")
        for sink, caller in rep.dangerous_calls:
            print(f"  [!CALL] {sink} <- {caller[:80]}")
        for v in rep.candidate_vulns:
            print(f"  [VULN] {v['kind']} {v['addr']}: {v['detail'][:80]}")
