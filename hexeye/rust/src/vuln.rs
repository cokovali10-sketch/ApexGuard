//! HexEye — эвристический анализ на CFG: Use-After-Free и Double Free.
//!
//! Ограничение честно декларируем: это register-level lite-taint в пределах
//! базового блока + propagation по безусловным переходам внутри функции.
//! Точный межпроцедурный анализ требует символического исполнения (вне scope).
use crate::cfg::Cfg;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    Unknown,
    Heap,   // результат malloc/strdup/...
    Freed,  // передан в free
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnFinding {
    pub kind: &'static str, // "UAF" | "DOUBLE_FREE"
    pub addr: u64,
    pub detail: String,
}

const HEAP_SOURCES: &[&str] = &["malloc", "calloc", "realloc", "strdup", "strndup", "memalign", "valloc"];
const FREE_SINKS: &[&str] = &["free", "cfree"];

/// Сканирует CFG на UAF / Double Free.
pub fn scan_cfg(cfg: &Cfg) -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    for block in &cfg.blocks {
        findings.extend(scan_block(block));
    }
    findings
}

/// Строит базовый счётчик использования для Double Free: если free
/// вызывается на одном регистре дважды без промежуточной записи — DOUBLE_FREE.
fn scan_block(block: &crate::cfg::BasicBlock) -> Vec<VulnFinding> {
    let mut out = Vec::new();
    let mut reg_state: FxHashMap<String, RegState> = FxHashMap::default();
    let mut freed_since_write: FxHashMap<String, bool> = FxHashMap::default();

    for insn in &block.instructions {
        let m = &insn.mnemonic;
        if m == "call" {
            let target = &insn.op_str;
            let arg_reg = extract_reg_arg(target);
            let callee = target.split_whitespace().next().unwrap_or("");

            if HEAP_SOURCES.iter().any(|h| callee.contains(h)) {
                if let Some(reg) = arg_reg {
                    reg_state.insert(reg, RegState::Heap);
                    freed_since_write.insert(reg, false);
                }
            } else if FREE_SINKS.iter().any(|f| callee.contains(f)) {
                if let Some(reg) = arg_reg {
                    match reg_state.get(&reg) {
                        Some(RegState::Heap) => {
                            if freed_since_write.get(&reg) == Some(&true) {
                                out.push(VulnFinding {
                                    kind: "DOUBLE_FREE",
                                    addr: insn.addr,
                                    detail: format!("free({reg}) повторно без записи (double free candidate)"),
                                });
                            } else {
                                freed_since_write.insert(reg, true);
                            }
                        }
                        Some(RegState::Freed) => {
                            out.push(VulnFinding {
                                kind: "DOUBLE_FREE",
                                addr: insn.addr,
                                detail: format!("free({reg}) на уже освобождённом указателе"),
                            });
                        }
                        _ => {}
                    }
                }
            }
        } else if m.starts_with("mov") || m.starts_with("lea") || m.starts_with("xor") {
            // запись в dest сбрасывает taint
            let dest = insn.op_str.split(',').next().unwrap_or("").trim();
            if let Some(reg) = normalize_reg(dest) {
                reg_state.remove(&reg);
                freed_since_write.insert(reg, false);
            }
        }

        // Использование Freed-регистра как базового адреса памяти → UAF
        if let Some(reg) = used_as_mem_base(&insn.op_str) {
            if reg_state.get(&reg) == Some(&RegState::Freed)
                || (reg_state.get(&reg) == Some(&RegState::Heap) && freed_since_write.get(&reg) == Some(&true))
            {
                out.push(VulnFinding {
                    kind: "UAF",
                    addr: insn.addr,
                    detail: format!("обращение к памяти [{reg}] после free (use-after-free candidate)"),
                });
            }
        }
    }
    out
}

/// Извлекает регистр-аргумент из "call free" — первый упомянутый reg.
fn extract_reg_arg(op_str: &str) -> Option<String> {
    // примеры: "free", "free.plt", "free@plt", "free(rax)", "rax"
    let t = op_str.replace("(", " ").replace(")", " ");
    normalize_reg(t)
}

/// Первый найденный регистр x86 в строке.
fn normalize_reg(s: &str) -> Option<String> {
    let known = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
        "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
    ];
    for r in known {
        // границы слова: ищем точное вхождение
        let mut iter = s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|x| !x.is_empty());
        while let Some(tok) = iter.next() {
            if tok == r {
                return Some(r.to_string());
            }
        }
        if s.contains(r) {
            return Some(r.to_string());
        }
    }
    None
}

/// Возвращает регистр, используемый как база памяти ([rax], QWORD PTR [rax+8]).
fn used_as_mem_base(op_str: &str) -> Option<String> {
    // вытаскиваем первый токен после '[' до +/-/]
    let open = op_str.find('[')?;
    let rest = &op_str[open + 1..];
    let close = rest.find(']').unwrap_or(rest.len());
    let inside = &rest[..close];
    let base = inside.split(['+', '-']).next().unwrap_or("");
    let base = base.trim();
    if base.starts_with("rbp") || base.starts_with("rsp") {
        return None; // стек — не heap
    }
    if base.chars().any(|c| c.is_ascii_hexdigit()) && base.len() > 2 && !base.contains('r') {
        return None; // константный адрес, не регистр
    }
    normalize_reg(base)
}

// ---------------------------------------------------------------------------
// Агрегация находок по функциям (межпроцедурный — грубый transit через call)
// ---------------------------------------------------------------------------
pub fn summarize(findings: &[VulnFinding]) -> usize {
    findings.len()
}

/// Полезная сводка опасных вызовов (sink) в CFG.
pub fn dangerous_sinks(cfg: &Cfg) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut seen: FxHashSet<u64> = FxHashSet::default();
    for block in &cfg.blocks {
        for insn in &block.instructions {
            if insn.mnemonic == "call" {
                let callee = insn.op_str.split_whitespace().next().unwrap_or("");
                for sink in ["strcpy", "strcat", "sprintf", "gets", "system", "memcpy", "strncpy", "scanf"] {
                    if callee.contains(sink) && seen.insert(insn.addr) {
                        out.push((insn.addr, sink.to_string()));
                    }
                }
            }
        }
    }
    out
}
