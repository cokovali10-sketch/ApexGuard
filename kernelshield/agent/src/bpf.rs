//! BPF-manager: загрузка скелетона, attach, доступ к картам, команды агента.
use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::sync::Arc;
use tokio::sync::Mutex;

mod kernelshield_skel {
    include!("bpf/kernelshield.skel.rs");
}
use kernelshield_skel::*;

pub struct BpfManager {
    skel: Option<kernelshield_skel::KernelshieldSkel>,
    /// глобальный флаг panic для user-space решений
    pub panic: std::sync::atomic::AtomicBool,
}

impl BpfManager {
    pub fn new() -> Self {
        Self { skel: None, panic: std::sync::atomic::AtomicBool::new(false) }
    }

    /// Загрузка и attach. Возвращает None, если .o не собран (см. build.rs warning).
    pub fn load_and_attach(&mut self) -> Result<()> {
        if std::path::Path::new("src/bpf/kernelshield.skel.rs").exists()
            || std::path::Path::new("../../probes/kernelshield.bpf.o").exists()
        {
            let mut builder = kernelshield_skel::KernelshieldSkelBuilder::default();
            builder.obj_builder.debug(false);
            let mut skel = builder.open().context("open skel")?.load()?;
            skel.attach().context("attach probes")?;
            self.skel = Some(skel);
        }
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.skel.is_some()
    }

    fn maps(&self) -> Option<(&libbpf_rs::Map, &libbpf_rs::Map, &libbpf_rs::Map)> {
        self.skel.as_ref().map(|s| {
            let m = s.maps();
            (&m.events, &m.blocked_pids, &m.panic_mode)
        })
    }

    /// Сборка ring buffer. Возвращает None если BPF не загружен.
    pub fn ring_buffer(
        &self,
        tx: crate::ringbuf::EventTx,
        drops: Arc<crate::ringbuf::DropCounter>,
    ) -> Option<libbpf_rs::RingBuffer> {
        let (events, _, _) = self.maps()?;
        crate::ringbuf::build_ring_buffer(events, tx, drops).ok()
    }

    /// Вставка IP в blocked_ips (LRU): ключ — u32 (native order, как в C-коде).
    pub fn block_ip(&self, ip: std::net::Ipv4Addr) -> Result<()> {
        let skel = self.skel.as_ref().context("BPF not loaded")?;
        let m = skel.maps();
        let key: u32 = u32::from(ip);
        let val: u8 = 1;
        m.blocked_ips.update(&key.to_ne_bytes(), &val.to_ne_bytes(), 0)?;
        Ok(())
    }

    /// Установка panic_mode (1/0) — AirGap на уровне ядра.
    pub fn set_panic_mode(&self, engage: bool) -> Result<()> {
        if let Some(skel) = &self.skel {
            let m = skel.maps();
            let key: u32 = 0;
            let val: u8 = if engage { 1 } else { 0 };
            m.panic_mode.update(&key.to_ne_bytes(), &val.to_ne_bytes(), 0)?;
        }
        self.panic.store(engage, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn is_panic(&self) -> bool {
        self.panic.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Пере-attach всех программ (reload).
    pub async fn reload(&mut self) -> Result<()> {
        if let Some(skel) = &self.skel {
            for prog in skel.progs().iter() {
                prog.detach()?;
            }
            skel.attach()?;
        }
        Ok(())
    }
}

/// Для Map update: libbpf-rs API требует &[u8] ключей. Упрощённый доступ.
pub type LockedBpf = Arc<Mutex<BpfManager>>;

/// Публикация события для метрик (оборачивается в metrics модуле).
pub fn new() -> BpfManager {
    BpfManager::new()
}
