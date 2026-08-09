// ApexConsole — 3D-топология сети.
// Узлы (host/container/honeypot), рёбра, утилиты для пула частиц.
import * as THREE from "three";

interface NodeDef {
  id: string;
  kind: "host" | "container" | "honeypot";
  pos: [number, number, number];
}

const NODES: NodeDef[] = [
  { id: "edge-router", kind: "host", pos: [-14, 2, -8] },
  { id: "app-01", kind: "host", pos: [-2, 0, -6] },
  { id: "app-02", kind: "host", pos: [6, 0, -10] },
  { id: "db-primary", kind: "container", pos: [12, -1, -4] },
  { id: "kafka", kind: "host", pos: [18, 3, 4] },
  { id: "honey-ssh", kind: "honeypot", pos: [-4, 4, 10] },
  { id: "honey-web", kind: "honeypot", pos: [4, 5, 14] },
  { id: "honey-ftp", kind: "honeypot", pos: [12, 4, 12] },
];

const EDGES: Array<[string, string]> = [
  ["edge-router", "app-01"],
  ["edge-router", "app-02"],
  ["app-01", "db-primary"],
  ["app-02", "kafka"],
  ["edge-router", "honey-ssh"],
  ["edge-router", "honey-web"],
  ["edge-router", "honey-ftp"],
];

const KIND_COLOR: Record<NodeDef["kind"], number> = {
  host: 0x3a6fff, container: 0x24c48b, honeypot: 0xc744ff,
};

export class Topology {
  private nodes = new Map<string, THREE.Mesh>();
  private positions = new Map<string, THREE.Vector3>();
  private nodesArr: THREE.Mesh[] = [];
  private honeypots: THREE.Vector3[] = [];

  constructor(private scene: THREE.Scene) {
    this.buildGraph();
    this.buildFloor();
  }

  private buildFloor() {
    const grid = new THREE.GridHelper(60, 30, 0x1c2c52, 0x0d1630);
    this.scene.add(grid);
  }

  private buildGraph() {
    NODES.forEach((n) => {
      const geo = n.kind === "honeypot"
        ? new THREE.TorusGeometry(1.1, 0.35, 16, 48)
        : new THREE.SphereGeometry(n.kind === "host" ? 1.4 : 0.9, 24, 24);
      const mat = new THREE.MeshStandardMaterial({
        color: KIND_COLOR[n.kind],
        emissive: KIND_COLOR[n.kind],
        emissiveIntensity: n.kind === "honeypot" ? 0.9 : 0.25,
        metalness: 0.3,
        roughness: 0.4,
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(...n.pos);
      mesh.userData = { id: n.id, kind: n.kind };
      this.scene.add(mesh);
      this.nodes.set(n.id, mesh);
      this.nodesArr.push(mesh);
      const v = new THREE.Vector3(...n.pos);
      this.positions.set(n.id, v);
      if (n.kind === "honeypot") this.honeypots.push(v);
    });

    EDGES.forEach(([a, b]) => {
      const pa = this.positions.get(a)!;
      const pb = this.positions.get(b)!;
      const geo = new THREE.BufferGeometry().setFromPoints([pa, pb]);
      const line = new THREE.Line(geo, new THREE.LineBasicMaterial({
        color: 0x2a4a88, transparent: true, opacity: 0.5,
      }));
      this.scene.add(line);
    });

    const light = new THREE.PointLight(0x88bbff, 120, 80);
    light.position.set(0, 15, 10);
    this.scene.add(light);
    this.scene.add(new THREE.AmbientLight(0x334, 0.6));
  }

  /** Случайный узел-источник атаки (обычно edge-router / host). */
  randomEdgeStart(): THREE.Vector3 {
    const router = this.positions.get("edge-router");
    if (router) return router;
    return this.nodesArr[0].position;
  }

  /** Случайная позиция ловушки (цель). */
  randomHoneypotPos(): THREE.Vector3 {
    if (this.honeypots.length === 0) return new THREE.Vector3();
    const i = Math.floor(Math.random() * this.honeypots.length);
    return this.honeypots[i];
  }

  /** Пульсация honeypot-узлов (небольшая анимация без аллокаций). */
  tick(_dt: number) {
    const t = performance.now() * 0.001;
    for (const mesh of this.nodesArr) {
      if (mesh.userData.kind === "honeypot") {
        const s = 1 + Math.sin(t * 2 + mesh.position.x) * 0.08;
        mesh.scale.setScalar(s);
      }
    }
  }

  refreshFilters() {
    // подключение DOM-фильтров — см. main.ts activeSev
  }
}
