//! KernelShield agent — оркестратор.
//!
//! Пайплайн: eBPF ring buffer (std-поток) → Unbounded mpsc → tokio EventPublisher
//! (client-streaming gRPC Publish с exponential backoff) → AegisBus.
//!
//! Дополнительно:
//!   * /metrics (Prometheus) на :9090
//!   * WatchCommands (AirGap/BlockIp/Reload) от Core применяются к BPF-картам
//!   * /proc обогащение: pid → exe, argv; cgroup → container_id (Docker/cri-o/k8s)

mod bpf;
mod cgroup;
mod grpc_client;
mod pb;
mod ringbuf;

use anyhow::Result;
use cgroup::CgroupResolver;
use prometheus::{Encoder, IntCounter, IntGauge, Opts, Registry, TextEncoder};
use ringbuf::RawEvent;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::grpc_client::{CommandHandlers, EventPublisher, PublisherMetrics, watch_commands};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "apexguard_agent=info,libbpf_rs=warn".into()),
        )
        .init();

    let endpoint = std::env::var("AEGIS_GRPC_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:50051".into());
    let listen = std::env::var("METRICS_LISTEN").unwrap_or_else(|_| "0.0.0.0:9090".into());
    info!(endpoint, "apexguard-agent starting");

    // ---------------- BPF ----------------
    let mut bpf = bpf::BpfManager::new();
    bpf.load_and_attach()?;
    if bpf.is_loaded() {
        info!("eBPF probes attached");
    } else {
        warn!("eBPF object missing; running in observer mode");
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<RawEvent>();
    let drops = ringbuf::DropCounter::new();
    if let Some(ring) = bpf.ring_buffer(tx.clone(), drops.clone()) {
        ringbuf::spawn_poll_thread(ring, drops.clone());
    }

    // ---------------- Resolver + converter ----------------
    let resolver = Arc::new(CgroupResolver::new(Duration::from_secs(60)));
    let metrics = Arc::new(PublisherMetrics::default());

    let converter = {
        let resolver = resolver.clone();
        let metrics = metrics.clone();
        Arc::new(move |raw: RawEvent| -> pb::events::aegis::v1::ThreatEvent {
            convert_event(raw, &resolver, &metrics)
        })
    };

    // ---------------- Prometheus ----------------
    let registry = Registry::new();
    let eps_gauge = IntGauge::with_opts(Opts::new("apexguard_events_processed", "events processed")).unwrap();
    let drop_gauge = IntGauge::with_opts(Opts::new("apexguard_ring_dropped", "ring drops")).unwrap();
    let reconnect_cnt = IntCounter::with_opts(Opts::new("apexguard_reconnects", "reconnects")).unwrap();
    registry.register(Box::new(eps_gauge.clone())).ok();
    registry.register(Box::new(drop_gauge.clone())).ok();
    registry.register(Box::new(reconnect_cnt.clone())).ok();

    let metrics_http = listen.clone();
    tokio::spawn(async move {
        serve_metrics(&metrics_http, registry).await;
    });

    // ---------------- WatchCommands ----------------
    let panic_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bpf_shared = Arc::new(std::sync::Mutex::new(bpf));
    {
        let bpf_handle = bpf_shared.clone();
        let handlers = CommandHandlers {
            on_airgap: Arc::new(move |engage: bool, reason: &str| {
                info!(engage, reason, "airgap command");
                if let Err(e) = bpf_handle.lock().unwrap().set_panic_mode(engage) {
                    error!(error = %e, "set_panic_mode failed");
                }
            }),
            on_block_ip: Arc::new(move |ip: u32| {
                let ip = std::net::Ipv4Addr::from(ip);
                info!(%ip, "block_ip command");
                if let Err(e) = bpf_handle.lock().unwrap().block_ip(ip) {
                    error!(error = %e, "block_ip failed");
                }
            }),
            on_reload: Arc::new(|_req| {
                info!("reload command");
            }),
        };
        let ep = endpoint.clone();
        let pf = panic_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_commands(ep, handlers, pf).await {
                error!(error = %e, "watch_commands exited");
            }
        });
    }

    // ---------------- Publisher ----------------
    let publisher = EventPublisher::new(endpoint, rx, converter, metrics.clone());
    tokio::spawn(async move {
        publisher.run().await;
    });

    // ---------------- Periodic metrics task ----------------
    let metrics_task = {
        let eps_gauge = eps_gauge.clone();
        let drop_gauge = drop_gauge.clone();
        let reconnect_cnt = reconnect_cnt.clone();
        let metrics = metrics.clone();
        let drops = drops.clone();
        async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                eps_gauge.set(metrics.published.load(std::sync::atomic::Ordering::Relaxed));
                drop_gauge.set(drops.get());
                reconnect_cnt.inc_by(
                    metrics.reconnect.swap(0, std::sync::atomic::Ordering::Relaxed),
                );
            }
        }
    };
    tokio::join!(metrics_task, std::future::pending::<()>());
    Ok(())
}

// ---------------------------------------------------------------------------
// Конвертация RawEvent → ThreatEvent (prost)
// ---------------------------------------------------------------------------
fn convert_event(
    raw: RawEvent,
    resolver: &CgroupResolver,
    metrics: &PublisherMetrics,
) -> pb::events::aegis::v1::ThreatEvent {
    use pb::events::aegis::v1::{event_source, event_type, severity, ThreatEvent};

    let (evt_type, sev, mitre) = classify(raw.evt_type, raw.blocked != 0);
    let container = resolver.resolve(raw.cgroup_id);
    let pid = raw.pid;
    let exe = resolve_exe(pid);
    let argv: Vec<String> = raw
        .argv
        .iter()
        .map(|a| String::from_utf8_lossy(a).trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut context = std::collections::HashMap::new();
    context.insert("filename".to_string(), cstr(&raw.filename).to_string());
    context.insert("exe_path".to_string(), exe);
    context.insert("argv".to_string(), argv.join(" "));
    context.insert("uid".to_string(), raw.uid.to_string());
    context.insert("gid".to_string(), raw.gid.to_string());
    context.insert("cgroup_path".to_string(), container.full_path.clone());
    if let Some(pid2) = &container.pod_id {
        context.insert("pod_id".to_string(), pid2.clone());
    }

    metrics.published.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    ThreatEvent {
        event_id: uuid::Uuid::now_v7().to_string(),
        ts: Some(prost_types::Timestamp {
            seconds: (now.as_secs()) as i64,
            nanos: now.subsec_nanos() as i32,
        }),
        source: event_source::EVENT_SOURCE_KERNELSHIELD as i32,
        r#type: evt_type,
        severity: sev,
        host_id: std::env::var("HOST_ID").unwrap_or_else(|_| "ks-0".into()),
        container_id: container.container_id.unwrap_or_default(),
        pid_namespace: String::new(),
        pid,
        ppid: raw.ppid,
        comm: cstr(&raw.comm).to_string(),
        context,
        mitre_technique: mitre.to_string(),
        blocked: raw.blocked != 0,
        raw_payload: vec![],
    }
}

fn classify(evt_type: u32, blocked: bool) -> (i32, i32, &'static str) {
    use pb::events::aegis::v1::{event_type, severity};
    match evt_type {
        1 => (
            event_type::EVENT_TYPE_EXECVE as i32,
            if blocked { severity::SEVERITY_CRITICAL } else { severity::SEVERITY_INFO } as i32,
            "T1059.004",
        ),
        2 => (event_type::EVENT_TYPE_CONNECT as i32, severity::SEVERITY_MEDIUM as i32, "T1071.001"),
        3 => (event_type::EVENT_TYPE_PTRACE as i32, severity::SEVERITY_HIGH as i32, "T1055.008"),
        4 => (event_type::EVENT_TYPE_PRIVILEGE as i32, severity::SEVERITY_HIGH as i32, "T1548.001"),
        5 => (event_type::EVENT_TYPE_NAMESPACE as i32, severity::SEVERITY_HIGH as i32, "T1610"),
        _ => (event_type::EVENT_TYPE_BLOCKED as i32, severity::SEVERITY_MEDIUM as i32, "T1498"),
    }
}

fn cstr(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("").trim_end_matches('\0')
}

fn resolve_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

async fn serve_metrics(addr: &str, registry: Registry) {
    use axum::{Router, routing::get};
    let app = Router::new().route("/metrics", get(move || {
        let registry = registry.clone();
        async move {
            let encoder = TextEncoder::new();
            let mf = registry.gather();
            let mut buf = Vec::new();
            if encoder.encode(&mf, &mut buf).is_ok() {
                String::from_utf8_lossy(&buf).to_string()
            } else {
                String::new()
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind metrics");
    info!(%addr, "metrics listening");
    axum::serve(listener, app).await.expect("metrics server");
}
