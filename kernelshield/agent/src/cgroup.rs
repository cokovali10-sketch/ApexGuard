//! Cgroup v2 → Container ID resolution.
//!
//! bpf_get_current_cgroup_id() возвращает kernfs inode директории cgroup.
//! С другой стороны, inode cgroup-директории можно получить через stat() на
//! /sys/fs/cgroup/<path> (kernfs inode совпадает). Алгоритм:
//!   1) собрать уникальные cgroup-пути всех процессов (из /proc/*/cgroup, v2 "0::");
//!   2) для каждого пути: stat("/sys/fs/cgroup/" + path) → st_ino;
//!   3) если ino == cgroup_id из BPF-события — это контейнер.
//!   4) распарсить путь в container_id / pod_id (docker/containerd/cri-o/k8s).
//!
//! Кэш по inode (TTL) — inode стабилен в течение жизни контейнера.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct ContainerMeta {
    pub container_id: Option<String>,
    pub runtime: Option<String>,
    pub pod_id: Option<String>,
    pub full_path: String,
}

struct Cache {
    map: HashMap<u64, ContainerMeta>,
    ctime: Instant,
}

pub struct CgroupResolver {
    cache: Mutex<Cache>,
    ttl: Duration,
}

impl CgroupResolver {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(Cache { map: HashMap::new(), ctime: Instant::now() }),
            ttl,
        }
    }

    /// Резолвинг по inode cgroup (из BPF-события).
    pub fn resolve(&self, cgroup_id: u64) -> ContainerMeta {
        let now = Instant::now();
        {
            let c = self.cache.lock().unwrap();
            if now.duration_since(c.ctime) < self.ttl {
                if let Some(m) = c.map.get(&cgroup_id) {
                    return m.clone();
                }
            }
        }
        let meta = self.resolve_via_fs(cgroup_id);
        let mut c = self.cache.lock().unwrap();
        c.map.insert(cgroup_id, meta.clone());
        c.ctime = now;
        if c.map.len() > 16_384 {
            c.map.clear();
        }
        meta
    }

    /// Быстрый путь для execve: у нас есть pid напрямую.
    pub fn resolve_pid(&self, pid: u32) -> ContainerMeta {
        read_cgroup_path(pid)
    }

    fn resolve_via_fs(&self, cgroup_id: u64) -> ContainerMeta {
        // 1) уникальные пути cgroup v2 всех процессов
        let mut seen = HashMap::new(); // path -> first pid
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for ent in rd.flatten() {
                let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                if pid == 0 {
                    continue;
                }
                let meta = read_cgroup_path(pid);
                if !meta.full_path.is_empty() {
                    seen.entry(meta.full_path.clone()).or_insert(pid);
                }
                if seen.len() > 4096 {
                    break;
                }
            }
        }
        // 2) stat директории → inode
        for (path, pid) in seen {
            let fs_path = format!("/sys/fs/cgroup/{}", path);
            if let Ok(md) = std::fs::metadata(&fs_path) {
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;
                #[cfg(unix)]
                if md.ino() == cgroup_id {
                    let mut meta = parse_cgroup_path(&path);
                    if meta.container_id.is_none() {
                        meta = read_cgroup_path(pid);
                    }
                    return meta;
                }
            }
        }
        ContainerMeta::default()
    }
}

/// Читает /proc/<pid>/cgroup и парсит путь v2.
pub fn read_cgroup_path(pid: u32) -> ContainerMeta {
    let path = format!("/proc/{}/cgroup", pid);
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .find(|l| l.starts_with("0::"))
            .map(|l| parse_cgroup_path(&l[3..]))
            .unwrap_or_default(),
        Err(_) => ContainerMeta::default(),
    }
}

/// Парсит cgroup-путь в container_id / pod_id.
pub fn parse_cgroup_path(path: &str) -> ContainerMeta {
    let mut meta = ContainerMeta {
        full_path: path.to_string(),
        ..Default::default()
    };

    // Docker (systemd driver): /docker/<id> или /docker-<id>.scope
    for marker in ["/docker/", "/docker-"] {
        if let Some(pos) = path.find(marker) {
            let rest = &path[pos + marker.len()..];
            meta.container_id = Some(rest.split('/').next().unwrap_or("").split('.').next().unwrap_or("").to_string());
            meta.runtime = Some("docker".into());
            break;
        }
    }
    // containerd / cri-o
    if meta.container_id.is_none() {
        for marker in ["cri-containerd-", "cri-o-", "container-", "cri-containerd/"] {
            if let Some(pos) = path.find(marker) {
                let rest = &path[pos + marker.len()..];
                meta.container_id = Some(rest.split('.').next().unwrap_or("").to_string());
                meta.runtime = Some(if marker.starts_with("cri-o") { "cri-o" } else { "containerd" }.into());
                break;
            }
        }
    }
    // Pod (kubepods-burstable-pod<uid>.slice)
    if meta.pod_id.is_none() {
        for marker in ["pod", "pod-"] {
            if let Some(pos) = path.find(marker) {
                let rest = &path[pos + marker.len()..];
                if rest.starts_with('-') || rest.starts_with('/') {
                    let id = rest.trim_start_matches(['-', '/']).split('.').next().unwrap_or("");
                    if !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        meta.pod_id = Some(id.to_string());
                    }
                }
            }
        }
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_path() {
        let m = parse_cgroup_path("/docker/9f3a7b1c0d2e4f5a6b7c8d9e0f1a2b3c");
        assert_eq!(m.container_id.as_deref(), Some("9f3a7b1c0d2e4f5a6b7c8d9e0f1a2b3c"));
        assert_eq!(m.runtime.as_deref(), Some("docker"));
    }

    #[test]
    fn parses_crio() {
        let m = parse_cgroup_path("/crio-abc123def456.scope");
        assert_eq!(m.container_id.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn parses_k8s_pod() {
        let m = parse_cgroup_path("/kubepods-burstable-pod12345678.slice/cri-containerd-99aa.scope");
        assert_eq!(m.pod_id.as_deref(), Some("12345678"));
        assert_eq!(m.container_id.as_deref(), Some("99aa"));
    }
}
