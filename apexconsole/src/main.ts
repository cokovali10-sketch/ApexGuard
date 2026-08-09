// ApexConsole — main.ts (production).
// 3D-топология (Three.js) + InstancedMesh пул событий (10k eps) + WS→gRPC-Gateway.
import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { Topology } from "./topology";
import { EventParticlePool } from "./instanced";
import { ApexGateway, type ThreatEvent } from "./gateway";
import { PanicController, mountPanicButton } from "./panic";

// ---------------------------------------------------------------------------
// Рендер
// ---------------------------------------------------------------------------
const renderer = new THREE.WebGLRenderer({
  canvas: document.getElementById("scene") as HTMLCanvasElement,
  antialias: true,
  powerPreference: "high-performance",
});
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.setClearColor(0x050810, 1);

const scene = new THREE.Scene();
scene.fog = new THREE.Fog(0x050810, 30, 90);

const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 500);
camera.position.set(0, 22, 34);
camera.lookAt(0, 0, 0);

const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;

const stars = new THREE.Points(
  new THREE.BufferGeometry().setFromPoints(
    Array.from({ length: 1200 }, () => new THREE.Vector3(
      (Math.random() - 0.5) * 160, (Math.random() - 0.5) * 160, (Math.random() - 0.5) * 160,
    )),
  ),
  new THREE.PointsMaterial({ color: 0x3a5b8c, size: 0.18, transparent: true, opacity: 0.7 }),
);
scene.add(stars);

const topology = new Topology(scene);
const particles = new EventParticlePool(scene);

// ---------------------------------------------------------------------------
// HUD / feed
// ---------------------------------------------------------------------------
let eps = 0, e2eLat = 0, alertCount = 0;

const SEV_COLOR: Record<string, number> = {
  CRITICAL: 0xff3b5c, HIGH: 0xff7a29, MEDIUM: 0xffc531,
  LOW: 0x3ec3ff, INFO: 0x6f8cff,
};

// XSS-safe: данные событий считаются untrusted, рендер только через textContent.
function pushFeed(ev: ThreatEvent) {
  const feed = document.getElementById("feed")!;
  if (feed.childElementCount > 300) feed.firstChild?.remove();

  const li = document.createElement("li");
  li.className = `sev-${ev.severity}`;

  const time = document.createElement("time");
  time.textContent = new Date(ev.ts).toLocaleTimeString();
  li.append(time);

  const source = document.createElement("span");
  source.textContent = ` [${ev.source}] ${ev.type}`;
  li.append(source);

  if (ev.mitre_technique) {
    const ttp = document.createElement("span");
    ttp.className = "ttp";
    ttp.textContent = ` ${ev.mitre_technique}`;
    li.append(ttp);
  }

  const detail = ev.comm ?? ev.context?.filename ?? ev.host_id ?? "";
  if (detail) {
    const d = document.createElement("span");
    d.textContent = ` ${detail}`;
    li.append(d);
  }

  if (ev.blocked) {
    const b = document.createElement("b");
    b.style.color = "var(--crit)";
    b.textContent = " BLOCKED";
    li.append(b);
  }
  feed.prepend(li);
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------
const SRC_ALL = ["KERNELSHIELD", "PULSEFUZZ", "SHADOWNET", "HEXEYE", "CORE"] as const;

function matchesFilters(ev: ThreatEvent): boolean {
  if (!activeSev.has(ev.severity)) return false;
  if (activeSrc.size > 0 && !activeSrc.has(ev.source)) return false;
  return true;
}

function bumpSrcStats(ev: ThreatEvent) {
  srcCounts[ev.source] = (srcCounts[ev.source] ?? 0) + 1;
  const el = document.getElementById(`c-${ev.source.toLowerCase()}`);
  if (el) el.textContent = String(srcCounts[ev.source]);
}

const srcCounts: Record<string, number> = {};
const activeSrc = new Set<string>(SRC_ALL);

const gateway = new ApexGateway(
  (ev) => {
    alertCount++;
    bumpSrcStats(ev);
    if (!matchesFilters(ev)) return;
    pushFeed(ev);
    const color = SEV_COLOR[ev.severity] ?? SEV_COLOR.INFO;
    const from = topology.randomEdgeStart();
    const to = topology.randomHoneypotPos();
    particles.emit(from, to, color);
  },
  (m) => {
    eps = m.event_rate_eps;
    e2eLat = m.latency_ms;
  },
  (s) => {
    document.querySelector(".status")!.textContent =
      s === "live" ? "LIVE" : s === "connecting" ? "CONNECTING..." : "OFFLINE";
    document.querySelector(".status .dot")!.classList.toggle("down", s === "offline");
  },
);

// ---------------------------------------------------------------------------
// Управление (REST через gRPC-Gateway)
// ---------------------------------------------------------------------------
const panic = new PanicController((engaged) => {
  // при Panic — очищаем частицы
  if (engaged) particles.clearAll();
});
mountPanicButton(panic);

document.getElementById("btn-block")!.onclick = async () => {
  const ip = (document.getElementById("ip-input") as HTMLInputElement).value.trim();
  if (!ip) return;
  await gateway.rpc("block-ip", { ip, persist: true });
};
document.getElementById("btn-reload")!.onclick = () => gateway.rpc("reload-probes", {});
document.getElementById("btn-fuzz")!.onclick = () =>
  gateway.rpc("trigger-fuzz", { target_url: "http://app:8080", protocol: "REST", concurrency: 50 });
document.getElementById("btn-honeypot")!.onclick = () =>
  gateway.rpc("spawn-honeypot", { services: ["SSH", "HTTP", "FTP"], llm_model: "qwen2.5:7b" });
document.getElementById("btn-analyze")!.onclick = () =>
  gateway.rpc("analyze-binary", { path: "/opt/samples/sample" });

// ---------------------------------------------------------------------------
// Фильтры (severity + source). Source-фильтры применяются и к WS-подписке,
// и мгновенно на клиенте; severity — мгновенно на клиенте.
// ---------------------------------------------------------------------------
const activeSev = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
document.querySelectorAll<HTMLButtonElement>("#severity-filters button").forEach((b) => {
  b.onclick = () => {
    b.classList.toggle("active");
    const sev = b.dataset.sev!;
    activeSev.has(sev) ? activeSev.delete(sev) : activeSev.add(sev);
  };
});

document.querySelectorAll<HTMLButtonElement>("#source-filters button").forEach((b) => {
  b.onclick = () => {
    b.classList.toggle("active");
    const src = b.dataset.src!;
    activeSrc.has(src) ? activeSrc.delete(src) : activeSrc.add(src);
  };
});

// ---------------------------------------------------------------------------
// Loop (60fps, zero-alloc)
// ---------------------------------------------------------------------------
let last = performance.now();
function animate() {
  requestAnimationFrame(animate);
  const now = performance.now();
  const dt = Math.min((now - last) / 1000, 0.05);
  last = now;

  (document.getElementById("m-eps")!.textContent as unknown) = eps;
  (document.getElementById("m-lat")!.textContent as unknown) = e2eLat.toFixed(1);
  (document.getElementById("m-alerts")!.textContent as unknown) = alertCount;

  controls.update();
  stars.rotation.y += 0.0003;
  particles.tick(dt, now);
  topology.tick(dt);
  renderer.render(scene, camera);
}

window.addEventListener("resize", () => {
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
});

function wsParams(): string {
  const src = activeSrc.size > 0 ? Array.from(activeSrc).join(",") : "";
  const q = new URLSearchParams();
  if (src) q.set("source", src);
  q.set("min_sev", "INFO");
  return `?${q.toString()}`;
}

gateway.connect(wsParams());
animate();