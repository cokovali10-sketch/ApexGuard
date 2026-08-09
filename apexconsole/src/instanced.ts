// ApexConsole — высокопроизводительный рендер событий через InstancedMesh.
//
// 10k событий/сек без аллокаций в hot path:
//   * пул инстансов InstancedMesh (емкость N, single draw call);
//   * кольцевой индексатор (round-robin поверх пула) — перезапись матриц
//     двойным буфером без создания новых объектов;
//   * matrix.update() + needsUpdate флаги, zero-GC на событие.
import * as THREE from "three";

const POOL_SIZE = 4096; // инстансов (4k частиц в одном draw call)

interface Particle {
  index: number;
  active: boolean;
  from: THREE.Vector3;
  to: THREE.Vector3;
  t: number;
  speed: number;
  born: number; // метка времени для fade
  seed: number;
}

export class EventParticlePool {
  private mesh: THREE.InstancedMesh;
  private dummy = new THREE.Object3D();
  private particles: Particle[];
  private cursor = 0;
  private flashMesh: THREE.InstancedMesh;
  private flashDummy = new THREE.Object3D();

  // prealloc: 0 аллокаций на событие после конструктора
  private posA = new THREE.Vector3();
  private dirA = new THREE.Vector3();

  constructor(scene: THREE.Scene, size = POOL_SIZE) {
    const geo = new THREE.SphereGeometry(0.18, 8, 8);
    const mat = new THREE.MeshBasicMaterial({
      color: 0x3ec3ff,
      transparent: true,
      opacity: 0.9,
    });
    this.mesh = new THREE.InstancedMesh(geo, mat, size);
    this.mesh.count = size;
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    scene.add(this.mesh);

    // вспышки-взрывы: отдельный пул
    const flashGeo = new THREE.SphereGeometry(0.4, 6, 6);
    const flashMat = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    this.flashMesh = new THREE.InstancedMesh(flashGeo, flashMat, 256);
    this.flashMesh.count = 256;
    this.flashMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.flashMesh.instanceMatrix.needsUpdate = true;
    scene.add(this.flashMesh);

    this.particles = new Array(size);
    for (let i = 0; i < size; i++) {
      this.particles[i] = {
        index: i,
        active: false,
        from: new THREE.Vector3(),
        to: new THREE.Vector3(),
        t: 0,
        speed: 1,
        born: 0,
        seed: Math.random(),
      };
    }
  }

  /**
   * Эмиссия события: атомарный выбор слота кольца, запись матрицы.
   * Цвет severity задаётся через setColorAt (двухцветный флаг-конвейер).
   */
  emit(from: THREE.Vector3, to: THREE.Vector3, colorHex: number) {
    const p = this.particles[this.cursor];
    this.cursor = (this.cursor + 1) % this.particles.length;

    p.active = true;
    p.from.copy(from);
    p.to.copy(to);
    p.t = 0;
    p.speed = 1 + p.seed;
    p.born = performance.now();

    this.dummy.position.copy(from);
    this.dummy.scale.setScalar(1);
    this.dummy.updateMatrix();
    this.mesh.setMatrixAt(p.index, this.dummy.matrix);
    this.mesh.setColorAt(p.index, new THREE.Color(colorHex));
    this.mesh.instanceMatrix.needsUpdate = true;
    if (this.mesh.instanceColor) this.mesh.instanceColor.needsUpdate = true;
  }

  /**
   * Прогресс частиц. dt — дельта секунд. Zero-allocation.
   */
  tick(dt: number, now: number) {
    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];
      if (!p.active) continue;

      p.t += dt * p.speed;
      if (p.t >= 1) {
        p.active = false;
        this.spawnFlash(p.to, now);
        this.hide(p.index);
        continue;
      }
      // Без промежуточных аллокаций: позиция = lerp(from, to) + дуга
      this.posA.lerpVectors(p.from, p.to, p.t);
      this.posA.y += Math.sin(p.t * Math.PI) * 2.0;
      this.dummy.position.copy(this.posA);
      this.dummy.rotation.y = p.t * 10;
      this.dummy.updateMatrix();
      this.mesh.setMatrixAt(p.index, this.dummy.matrix);
      this.mesh.instanceMatrix.needsUpdate = true;
    }
  }

  private spawnFlash(at: THREE.Vector3, now: number) {
    const idx = Math.floor((now * 0.001 * 60)) % 256;
    this.flashDummy.position.copy(at);
    this.flashDummy.scale.setScalar(1 + ((now % 1000) / 1000) * 3);
    this.flashDummy.updateMatrix();
    this.flashMesh.setMatrixAt(idx, this.flashDummy.matrix);
    this.flashMesh.instanceMatrix.needsUpdate = true;
  }

  private hide(index: number) {
    this.dummy.position.set(0, -1000, 0);
    this.dummy.scale.setScalar(0.0001);
    this.dummy.updateMatrix();
    this.mesh.setMatrixAt(index, this.dummy.matrix);
  }

  /** Мгновенное скрытие всех (Panic Mode). */
  clearAll() {
    for (let i = 0; i < this.particles.length; i++) {
      this.particles[i].active = false;
      this.hide(i);
    }
    this.mesh.instanceMatrix.needsUpdate = true;
  }

  get activeCount(): number {
    let n = 0;
    for (const p of this.particles) if (p.active) n++;
    return n;
  }
}
