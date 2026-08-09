//! HexEye — параллельный сканер секретов (hardcoded keys/tokens/passwords).
//!
//! Быстрее Python-версии в десятки раз за счёт:
//!   * memmap (zero-copy чтение файла),
//!   * rayon-параллелизм по секциям .rodata/.data/.rdata,
//!   * regex::bytes (без UTF-8 валидации, memchr-ускорение).
use rayon::prelude::*;
use regex::bytes::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SecretHit {
    pub rule: &'static str,
    pub value: String,
    pub offset: u64,
    pub section: String,
}

// Порядок важен: специфичные паттерны раньше общих.
static RULES: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("AWS_SECRET", r"(?i)aws_secret[^a-z0-9]{0,3}[A-Za-z0-9/+=]{40}"),
    ("GCP_KEY", r"AIza[0-9A-Za-z_-]{35}"),
    ("GITHUB_TOKEN", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("RSA_PRIVATE", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("PEM_CERT", r"-----BEGIN CERTIFICATE-----"),
    ("PASSWORD_ASSIGN", r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]"),
    ("API_KEY", r"(?i)api[_-]?key['\":=\s]+[A-Za-z0-9]{20,}"),
    ("MYSQL_DSN", r"mysql://[^\s]+:[^\s@]+@"),
    ("PG_DSN", r"postgres(ql)?://[^\s]+:[^\s@]+@"),
    ("SLACK_TOKEN", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("SQUID_PASSWORD", r"(?i)squid_password|router_password"),
];

pub struct SecretScanner {
    compiled: Vec<(&'static str, Regex)>,
}

impl SecretScanner {
    pub fn new() -> Self {
        let compiled = RULES
            .iter()
            .filter_map(|(name, pat)| Regex::new(pat).ok().map(|re| (*name, re)))
            .collect();
        Self { compiled }
    }

    /// Сканирует диапазон файла (start..end) по всем правилам.
    pub fn scan_range(&self, data: &[u8], start: u64, end: u64, section: &str) -> Vec<SecretHit> {
        let lo = (start as usize).min(data.len());
        let hi = (end as usize).min(data.len());
        if lo >= hi {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for (name, re) in &self.compiled {
            for m in re.find_iter(&data[lo..hi]) {
                let value = String::from_utf8_lossy(m.as_bytes());
                if value.len() > 128 {
                    continue; // слишком длинный «секрет» — шум
                }
                hits.push(SecretHit {
                    rule: name,
                    value: value.into_owned(),
                    offset: lo as u64 + m.start() as u64,
                    section: section.to_string(),
                });
            }
        }
        hits
    }

    /// Параллельный скан списка секций (данные). Запускается через rayon.
    pub fn scan_sections(
        &self,
        data: &[u8],
        sections: &[(String, u64, u64)], // (name, file_offset, size)
        threads: usize,
    ) -> Vec<SecretHit> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| {
            sections
                .par_iter()
                .flat_map(|(name, off, size)| self.scan_range(data, *off, *off + *size, name))
                .collect()
        })
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}
