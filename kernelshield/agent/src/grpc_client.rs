//! gRPC-клиент шины AegisBus.
//!
//! 1) `EventPublisher` — долгоживущий client-streaming Publish() с экспоненциальным
//!    backoff (backoff crate), батчированием и watermark-лимитом на несинхронизированные
//!    события (drop-oldest при переполнении).
//! 2) `WatchLoop` — подписка на WatchCommands (AirGap / BlockIp / Reload) и применение
//!    к BPF-картам через коллбэки.

use crate::pb::events::aegis::v1::aegis_core_client::AegisCoreClient;
use crate::pb::events::aegis::v1::command::Action as CommandAction;
use crate::pb::events::aegis::v1::{Command, ReloadRequest, ThreatEvent, WatchRequest};
use crate::ringbuf::RawEvent;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tonic::transport::Channel;
use tracing::{error, info, warn};

const BATCH_INTERVAL_MS: u64 = 25; // 40 батчей/с
const PENDING_WATERMARK: usize = 200_000;

/// Счётчики событий (передаются в Prometheus).
#[derive(Default)]
pub struct PublisherMetrics {
    pub published: AtomicU64,
    pub dropped: AtomicU64,
    pub reconnect: AtomicU64,
    pub seq: AtomicU64,
}

pub struct EventPublisher {
    endpoint: String,
    rx: mpsc::UnboundedReceiver<RawEvent>,
    converter: Arc<dyn Fn(RawEvent) -> ThreatEvent + Send + Sync>,
    metrics: Arc<PublisherMetrics>,
}

impl EventPublisher {
    pub fn new(
        endpoint: String,
        rx: mpsc::UnboundedReceiver<RawEvent>,
        converter: Arc<dyn Fn(RawEvent) -> ThreatEvent + Send + Sync>,
        metrics: Arc<PublisherMetrics>,
    ) -> Self {
        Self { endpoint, rx, converter, metrics }
    }

    /// Основной цикл: connect → publish → reconnect с backoff.
    pub async fn run(self) {
        loop {
            match self.connect_and_publish().await {
                Ok(()) => {
                    info!("publish stream closed cleanly; reconnecting");
                }
                Err(e) => error!(error = %e, "publish stream error"),
            }
            self.metrics.reconnect.fetch_add(1, Ordering::Relaxed);
            sleep_backoff().await;
        }
    }

    async fn connect_and_publish(&self) -> anyhow::Result<()> {
        // mTLS/SPIFFE: tonic поддерживает TLS; сертификаты задаются env.
        let channel = Channel::from_shared(self.endpoint.clone())?
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .connect()
            .await?;
        let mut client = AegisCoreClient::new(channel);
        let mut out = client.publish().await?.into_inner();

        let mut pending: std::collections::VecDeque<ThreatEvent> = Default::default();
        let mut tick = interval(Duration::from_millis(BATCH_INTERVAL_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    // watermark: drop-oldest раньше, чем переполним память
                    while pending.len() > PENDING_WATERMARK {
                        pending.pop_front();
                        self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    // отсылаем накопленные события (долгоживущий стрим не закрываем)
                    while let Some(ev) = pending.pop_front() {
                        if let Err(status) = out.send(ev.clone()).await {
                            pending.push_front(ev); // вернём в очередь для ретрая
                            return Err(status.into());
                        }
                    }
                }
                maybe = self.rx.recv() => {
                    match maybe {
                        Some(raw) => {
                            let mut ev = (self.converter)(raw);
                            let seq = self.metrics.seq.fetch_add(1, Ordering::Relaxed) + 1;
                            ev.event_id = format!("{seq}");
                            pending.push_back(ev);
                        }
                        None => {
                            // продюсер закрыт: финализируем стрим, ждём ack
                            let ack = out.finish().await?;
                            info!(accepted = ack.accepted, "publish finalized");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

fn sleep_backoff() -> tokio::time::Sleep {
    let mut b = ExponentialBackoff::default();
    b.initial_interval = Duration::from_millis(100);
    b.multiplier = 2.0;
    b.max_interval = Duration::from_secs(30);
    b.max_elapsed_time = None;
    let d = b.next_backoff().unwrap_or(Duration::from_secs(1));
    tokio::time::sleep(d)
}

// ---------------------------------------------------------------------------
// WatchCommands: канал команд от Core (AirGap / BlockIp / Reload)
// ---------------------------------------------------------------------------

pub struct CommandHandlers {
    pub on_airgap: Arc<dyn Fn(bool, &str) + Send + Sync>,
    pub on_block_ip: Arc<dyn Fn(u32) + Send + Sync>,
    pub on_reload: Arc<dyn Fn(ReloadRequest) + Send + Sync>,
}

/// Держит WatchCommands стрим открытым и применяет команды. Atomic-флаг panic.
pub async fn watch_commands(
    endpoint: String,
    handlers: CommandHandlers,
    panic_flag: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut b = ExponentialBackoff::default();
    b.initial_interval = Duration::from_millis(200);
    b.max_interval = Duration::from_secs(30);
    b.max_elapsed_time = None;

    loop {
        let channel = match Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "watch channel connect failed");
                let d = b.next_backoff().unwrap_or(Duration::from_secs(1));
                tokio::time::sleep(d).await;
                continue;
            }
        };
        let mut client = AegisCoreClient::new(channel);
        let mut stream = match client.watch_commands(WatchRequest {}).await {
            Ok(r) => r.into_inner(),
            Err(e) => {
                warn!(error = %e, "watch_commands failed");
                let d = b.next_backoff().unwrap_or(Duration::from_secs(1));
                tokio::time::sleep(d).await;
                continue;
            }
        };
        while let Some(cmd) = stream.message().await? {
            apply_command(cmd, &handlers, &panic_flag);
        }
    }
}

fn apply_command(cmd: Command, handlers: &CommandHandlers, panic_flag: &AtomicBool) {
    match cmd.action {
        Some(CommandAction::AirGap(a)) => {
            panic_flag.store(a.engage, Ordering::SeqCst);
            (handlers.on_airgap)(a.engage, &a.reason);
        }
        Some(CommandAction::BlockIp(b)) => {
            if let Ok(ip) = b.ip.parse::<std::net::Ipv4Addr>() {
                (handlers.on_block_ip)(u32::from(ip));
            }
        }
        Some(CommandAction::ReloadProbes(r)) => (handlers.on_reload)(r),
        None => {}
    }
}
