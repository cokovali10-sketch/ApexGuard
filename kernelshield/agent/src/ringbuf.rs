//! Ring buffer consumer (zero-copy) + событийная очередь.
//!
//! libbpf ring_buffer poll — блокирующий вызов, поэтому живёт на выделенном
//! std-потоке. Событие копируется ровно один раз из ядерного слота в
//! heap-структуру и передаётся в tokio UnboundedSender. Канал unbounded:
//! отсутствие сетевой готовности gRPC НЕ должно приводить к переполнению
//! кольца ядра и потере событий безопасности.

use anyhow::Result;
use libbpf_rs::{Map, RingBuffer, RingBufferBuilder};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

/// Структура события — зеркалит `struct exec_event` из kernelshield.bpf.c.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawEvent {
    pub evt_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub ts: u64,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub blocked: u8,
    pub container_escape: u8,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argv: [[u8; 64]; 16],
}

pub type EventTx = mpsc::UnboundedSender<RawEvent>;
pub type EventRx = mpsc::UnboundedReceiver<RawEvent>;

/// Счётчик потерянных событий (для Prometheus /metrics).
#[derive(Default)]
pub struct DropCounter(std::sync::atomic::AtomicU64);

impl DropCounter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicU64::new(0)))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Коллбэк для RingBufferBuilder: копия слота → канал, zero-lock.
pub fn make_callback(tx: EventTx, drops: Arc<DropCounter>) -> impl FnMut(&[u8]) -> i32 + Send + 'static {
    move |data: &[u8]| {
        if data.len() < std::mem::size_of::<RawEvent>() {
            return 0;
        }
        // Единственный аллок на событие — неизбежен при передаче в user-space.
        let ev: RawEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawEvent) };
        if tx.send(ev).is_err() {
            drops.inc();
        }
        0
    }
}

/// Сборка RingBuffer из BPF-карты `events`.
pub fn build_ring_buffer(events_map: &Map, tx: EventTx, drops: Arc<DropCounter>) -> Result<RingBuffer> {
    let mut rbb = RingBufferBuilder::new();
    rbb.add(events_map, make_callback(tx, drops))?;
    Ok(rbb.build()?)
}

/// Запуск блокирующего poll на отдельном потоке (RINGBUF_CAP slots max_entries=1MB).
pub fn spawn_poll_thread(ring: RingBuffer, drops: Arc<DropCounter>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ks-ringbuf".into())
        .spawn(move || loop {
            if let Err(e) = ring.poll(250) {
                warn!(error = %e, "ring poll error");
                drops.inc();
            }
        })
        .expect("spawn ringbuf thread")
}
