// ApexConsole — Panic Mode (Air-Gap) control.
// Экстренная изоляция: вызов POST /v1/airgap {engage:true} → Core рассылает
// команду агентам (eBPF panic_mode + no-egress) и блокирует фаззер/ловушки.
const PANIC_KEY = "apex.panic.engaged";

export class PanicController {
  private engaged = false;
  private readonly onToggle: (engaged: boolean) => void;

  constructor(onToggle: (engaged: boolean) => void) {
    this.onToggle = onToggle;
    this.engaged = localStorage.getItem(PANIC_KEY) === "1";
  }

  isEngaged(): boolean {
    return this.engaged;
  }

  /** Вызов экстренной изоляции (идемпотентно). */
  async engage(reason = "operator-initiated"): Promise<boolean> {
    return this.call(true, reason);
  }

  async release(reason = "operator-release"): Promise<boolean> {
    return this.call(false, reason);
  }

  private async call(engage: boolean, reason: string): Promise<boolean> {
    try {
      const resp = await fetch("/v1/airgap", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ engage, reason }),
      });
      if (!resp.ok) throw new Error(`airgap http ${resp.status}`);
      const data = (await resp.json()) as { engaged: boolean };
      this.engaged = data.engaged;
      localStorage.setItem(PANIC_KEY, this.engaged ? "1" : "0");
      this.onToggle(this.engaged);
      return this.engaged;
    } catch (err) {
      console.error("[panic] airgap call failed", err);
      return this.engaged;
    }
  }
}

/** Привязка кнопки #btn-panic (уже в разметке index.html). */
export function mountPanicButton(controller: PanicController) {
  const btn = document.getElementById("btn-panic") as HTMLButtonElement;
  if (!btn) return;
  btn.textContent = controller.isEngaged() ? "UN-GAP (release)" : "AIR-GAP (panic)";
  btn.onclick = async () => {
    if (!controller.isEngaged()) {
      if (!confirm("Экстренная изоляция (Air-Gap)? Все egress-соединения будут заблокированы на уровне ядра.")) {
        return;
      }
      await controller.engage();
    } else {
      await controller.release();
    }
  };
  controller.onToggle = (eng) => {
    btn.textContent = eng ? "UN-GAP (release)" : "AIR-GAP (panic)";
    btn.classList.toggle("engaged", eng);
  };
}
