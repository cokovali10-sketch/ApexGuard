//! HexEye — построение Control Flow Graph (CFG) из дизассемблированного кода.
//!
//!   * линейная разметка: базовый блок = непрерывная цепочка до ветвления;
//!   * рёбра: jmp → target; jcc → target + fallthrough; ret → exit;
//!   * детекция циклов: поиск обратных рёбер (back edge) в DFS (алгоритм Тарьяна);
//!   * вершины хранят инструкции для последующего анализа (vuln.rs).
use capstone::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    pub addr: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<Insn>,
}

#[derive(Debug, Default, Serialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    /// adjacency: block_id -> set(block_id)
    pub edges: Vec<Vec<usize>>,
    pub back_edges: Vec<(usize, usize)>,
    pub cycles: Vec<Vec<usize>>,
    pub loops: usize,
}

impl Cfg {
    pub fn build(code: &[u8], base_addr: u64, arch: Arch) -> anyhow::Result<Cfg> {
        let cs = match arch {
            Arch::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?,
            Arch::Arm => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()?,
            Arch::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()?,
        };
        let insns = cs.disasm_all(code, base_addr)?;

        // ---- фаза 1: разметка базовых блоков ----
        let mut block_starts: FxHashSet<u64> = FxHashSet::default();
        block_starts.insert(base_addr);
        let mut branch_targets: FxHashSet<u64> = FxHashSet::default();
        let mut next_of = FxHashMap::default(); // instr_addr -> next instr addr
        let mut terminator: FxHashMap<u64, u64> = FxHashMap::default(); // instr -> block start

        let addr_list: Vec<u64> = insns.iter().map(|i| i.address()).collect();
        for w in addr_list.windows(2) {
            next_of.insert(w[0], w[1]);
        }

        // терминаторы: инструкции, после которых блок заканчивается
        for insn in insns.iter() {
            let m = insn.mnemonic().to_string();
            let is_term = m.starts_with("jmp")
                || m.starts_with("j")
                || m.starts_with("call")
                || m.starts_with("ret")
                || m.starts_with("loop");
            if is_term {
                let op = insn.op_str().to_string();
                // прямой jmp/jcc с адресом — расщепляем target
                if let Some(addr) = parse_target(&op) {
                    if m != "call" {
                        branch_targets.insert(addr);
                    }
                }
                terminator.insert(insn.address(), insn.address());
            }
        }
        for insn in insns.iter() {
            let next = next_of.get(&insn.address());
            if let Some(n) = next {
                if branch_targets.contains(&n) {
                    block_starts.insert(*n);
                }
            }
        }

        // ---- фаза 2: сборка блоков ----
        let mut starts: Vec<u64> = block_starts.iter().copied().collect();
        starts.sort_unstable();

        let mut id_of: FxHashMap<u64, usize> = FxHashMap::default();
        let mut blocks: Vec<BasicBlock> = Vec::new();
        for (i, &s) in starts.iter().enumerate() {
            id_of.insert(s, i);
            blocks.push(BasicBlock {
                id: i,
                start: s,
                end: s,
                instructions: Vec::new(),
            });
        }
        let mut cur = usize::MAX;
        for insn in insns.iter() {
            let a = insn.address();
            if let Some(&bid) = id_of.get(&a) {
                cur = bid;
            }
            if cur == usize::MAX {
                continue;
            }
            let b = &mut blocks[cur];
            b.end = a;
            b.instructions.push(Insn {
                addr: a,
                bytes: insn.bytes().iter().map(|x| format!("{x:02x}")).collect(),
                mnemonic: insn.mnemonic().to_string(),
                op_str: insn.op_str().to_string(),
            });
        }

        // ---- фаза 3: рёбра ----
        let n = blocks.len();
        let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut cfg = Cfg { blocks, edges, ..Default::default() };

        for b in 0..n {
            let last = cfg.blocks[b].instructions.last().map(|i| i.clone());
            let Some(last) = last else { continue };
            let m = &last.mnemonic;
            if m.starts_with("ret") || m.starts_with("call") {
                continue; // выход/вызов не меняет линейный CFG
            }
            if m.starts_with("jmp") {
                if let Some(t) = parse_target(&last.op_str) {
                    if let Some(&tb) = id_of.get(&t) {
                        add_edge(&mut cfg.edges, b, tb);
                    }
                }
            } else if m.starts_with("j") {
                if let Some(t) = parse_target(&last.op_str) {
                    if let Some(&tb) = id_of.get(&t) {
                        add_edge(&mut cfg.edges, b, tb);
                    }
                }
                // fallthrough
                if let Some(next) = next_of.get(&last.addr) {
                    if let Some(&nb) = id_of.get(next) {
                        add_edge(&mut cfg.edges, b, nb);
                    }
                }
            } else if m.starts_with("loop") {
                if let Some(t) = parse_target(&last.op_str) {
                    if let Some(&tb) = id_of.get(&t) {
                        add_edge(&mut cfg.edges, b, tb);
                    }
                }
                if let Some(next) = next_of.get(&last.addr) {
                    if let Some(&nb) = id_of.get(next) {
                        add_edge(&mut cfg.edges, b, nb);
                    }
                }
            }
        }

        cfg.detect_cycles();
        Ok(cfg)
    }

    /// Детекция циклов: DFS с цветами (white/grey/black), обратные рёбра.
    fn detect_cycles(&mut self) {
        let n = self.blocks.len();
        let mut color = vec![0u8; n]; // 0 white, 1 grey, 2 black
        let mut path: Vec<usize> = Vec::new();
        let mut back_edges: Vec<(usize, usize)> = Vec::new();

        fn dfs(
            u: usize,
            adj: &[Vec<usize>],
            color: &mut [u8],
            path: &mut Vec<usize>,
            back: &mut Vec<(usize, usize)>,
        ) {
            color[u] = 1;
            path.push(u);
            for &v in &adj[u] {
                if color[v] == 0 {
                    dfs(v, adj, color, path, back);
                } else if color[v] == 1 {
                    back.push((u, v)); // обратное ребро → цикл
                }
            }
            color[u] = 2;
            path.pop();
        }

        for s in 0..n {
            if color[s] == 0 {
                dfs(s, &self.edges, &mut color, &mut path, &mut back_edges);
            }
        }

        self.back_edges = back_edges;
        self.loops = back_edges.len();

        // для каждого обратного ребра извлекаем простой цикл
        for &(u, v) in &self.back_edges {
            let mut cycle = vec![v];
            let mut cur = u;
            while cur != v {
                cycle.push(cur);
                // ищем предшественника в пути (грубо: в графе)
                let mut found = None;
                for &p in &self.edges[cur] {
                    let _ = p;
                }
                // шаг назад по обратным ссылкам: используем предшественника по DFS-дереву
                found = self
                    .edges
                    .iter()
                    .enumerate()
                    .find(|(_, e)| e.contains(&cur))
                    .map(|(i, _)| i);
                if let Some(p) = found {
                    cur = p;
                } else {
                    break;
                }
                if cycle.len() > 64 {
                    break;
                }
            }
            cycle.push(v);
            self.cycles.push(cycle);
        }
    }
}

fn add_edge(edges: &mut [Vec<usize>], from: usize, to: usize) {
    if !edges[from].contains(&to) {
        edges[from].push(to);
    }
}

/// Парсинг целевого адреса из операнда ("0x401000", "1000").
fn parse_target(op: &str) -> Option<u64> {
    let trimmed = op.trim();
    let first = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let first = first.trim_end_matches(':');
    if first.starts_with("0x") || first.starts_with("0X") {
        u64::from_str_radix(&first[2..], 16).ok()
    } else {
        first.parse::<u64>().ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    Arm,
    Arm64,
}
