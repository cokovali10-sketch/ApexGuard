// ApexConsole — связь с gRPC-Gateway / WebSocket-мостом ApexCore.
//   * события: WebSocket → /ws/events (JSON ThreatEvent + SystemMetric);
//   * команды: REST → /v1/* (grpc-gateway).
export interface ThreatEvent {
  event_id: string;
  ts: string;
  source: string;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  host_id: string;
  container_id?: string;
  pid?: number;
  comm?: string;
  context: Record<string, string>;
  mitre_technique?: string;
  blocked?: boolean;
}

export interface SystemMetric {
  host_id: string;
  event_rate_eps: number;
  latency_ms: number;
  ts: string;
}

export type WsMessage = ThreatEvent | SystemMetric;

export class ApexGateway {
  private ws: WebSocket | null = null;
  private reconnectDelay = 500;
  private readonly onEvent: (ev: ThreatEvent) => void;
  private readonly onMetric: (m: SystemMetric) => void;
  private readonly onStatus: (s: "connecting" | "live" | "offline") => void;

  constructor(
    onEvent: (ev: ThreatEvent) => void,
    onMetric: (m: SystemMetric) => void,
    onStatus: (s: "connecting" | "live" | "offline") => void,
  ) {
    this.onEvent = onEvent;
    this.onMetric = onMetric;
    this.onStatus = onStatus;
  }

  connect(params?: string) {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${location.host}/ws/events${params ?? ""}`;
    this.onStatus("connecting");
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      this.reconnectDelay = 500;
      this.onStatus("live");
    };
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data as string) as WsMessage;
        if ("event_rate_eps" in data) {
          this.onMetric(data as SystemMetric);
        } else {
          this.onEvent(data as ThreatEvent);
        }
      } catch {
        /* malformed frame — skip */
      }
    };
    ws.onerror = () => this.onStatus("offline");
    ws.onclose = () => {
      this.onStatus("offline");
      this.ws = null;
      setTimeout(() => this.connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000); // exp backoff
    };
    this.ws = ws;
  }

  /** Команда в шину через gRPC-Gateway REST. */
  async rpc(cmd: string, body: unknown): Promise<unknown> {
    const resp = await fetch(`/v1/${cmd}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(`${cmd} -> http ${resp.status}`);
    }
    return resp.json();
  }

  close() {
    this.ws?.close();
    this.ws = null;
  }
}
