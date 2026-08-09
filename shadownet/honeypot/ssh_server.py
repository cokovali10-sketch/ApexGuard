#!/usr/bin/env python3
# ShadowNet — асинхронный SSH-эмулятор (honeypot) с генеративным ИИ.
#
# При входящем подключении:
#   1) asyncio-задача асинхронно поднимает изолированный контейнер
#      (≤500ms, RAM 128MB, no egress) с фейковой ФС + honeytokens;
#   2) shell-эмулятор отвечает на команды из фейковой ФС контейнера,
#      произвольные команды проксируются в Ollama (локальная LLM);
#   3) каждое действие маппится на MITRE ATT&CK и публикуется в AegisBus;
#   4) чтение файла с honeytoken'ом фиксируется как событие TOKEN_EXPOSED.
#
# Run: python shadownet/honeypot/ssh_server.py --port 2222 --docker
import argparse
import asyncio
import logging
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from shadownet.containers.orchestrator import DockerOrchestrator
from shadownet.events.bus import AegisBus
from shadownet.honeytokens.generator import FakeFSBuilder, HoneytokenGenerator, HoneytokenRegistry
from shadownet.llm.client import OllamaClient
from shadownet.mitre.mapper import MITREMapper
from shadownet.web.api import ShadowNetAPI, run_api

log = logging.getLogger("shadownet.ssh")

# Детерминированные команды (без LLM)
KNOWN = {
    "whoami": lambda _: "root\n",
    "id": lambda _: "uid=0(root) gid=0(root) groups=0(root)\n",
    "hostname": lambda _: "prod-db-07\n",
    "pwd": lambda _: "/root\n",
    "uname -a": lambda _: "Linux prod-db-07 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
    "uptime": lambda _: " 14:22:31 up 312 days,  5:12,  1 user,  load average: 0.04, 0.01, 0.00\n",
    "ip addr": lambda _: "eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> inet 172.19.0.7/16 brd 172.19.255.255\n",
    "ifconfig": lambda _: "eth0      Link encap:Ethernet  HWaddr 02:42:ac:13:00:07\n          inet addr:172.19.0.7  Bcast:172.19.255.255  Mask:255.255.0.0\n",
    "df -h": lambda _: "Filesystem      Size  Used Avail Use% Mounted on\noverlay          20G   4.2G   16G  22% /\n",
    "free -m": lambda _: "              total        used        free      shared  buff/cache   available\nMem:           3968        3124         124         168         720          512\n",
}


@dataclass
class SessionState:
    peer: str = ""
    user: str = "unknown"
    cwd: str = "/root"
    started: float = field(default_factory=time.time)
    commands: list[str] = field(default_factory=list)
    honeypot_fs: Path | None = None
    container_id: str | None = None


class ShadowSSHServer(asyncssh.SSHServer):
    def __init__(self, bus: AegisBus, mitre: MITREMapper, llm: OllamaClient,
                 orch: DockerOrchestrator | None, registry: HoneytokenRegistry | None):
        self.bus = bus
        self.mitre = mitre
        self.llm = llm
        self.orch = orch
        self.registry = registry

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self.conn = conn
        self.state = SessionState(
            peer=conn.get_extra_info("peername")[0] if conn.get_extra_info("peername") else "?",
        )
        # Защита от спама ловушек с одного IP.
        if self.orch is not None and not self.orch.rate_limit_ok(self.state.peer):
            log.warning("[%s] rate-limited honeypot spawn", self.state.peer)
            return
        # Асинхронно поднимаем honeypot-контейнер с токенами.
        if self.orch is not None:
            asyncio.ensure_future(self._spawn_honeypot())

    async def _spawn_honeypot(self):
        try:
            gen = HoneytokenGenerator()
            root = Path(tempfile.mkdtemp(prefix=f"deception-{self.state.peer.replace('.', '-')}-"))
            fs = FakeFSBuilder(root, gen)
            tokens = fs.build()
            if self.registry:
                self.registry.register(tokens)
            container = await self.orch.spawn(f"deception-{uuid.uuid4().hex[:12]}", str(root))
            self.state.honeypot_fs = root
            self.state.container_id = container.id
            log.info("[%s] honeypot %s ready", self.state.peer, container.id[:12])
        except Exception as e:
            log.warning("[%s] container spawn failed: %s", self.state.peer, e)

    def connection_lost(self, exc: BaseException | None):
        # Гарантированная уборка: контейнер живёт только во время сессии.
        if self.orch is not None and self.state.container_id:
            asyncio.ensure_future(self.orch.remove(self.state.container_id))
            log.info("[%s] honeypot container %s removed", self.state.peer, self.state.container_id[:12])
        self.state.container_id = None

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.state.user = username
        self.bus.emit_anomaly(
            "T1078.001", severity="MEDIUM",
            context={"auth_user": username, "src_ip": self.state.peer},
        )
        return True

    def session_requested(self):
        return ShadowShellSession(self.state, self.llm, self.bus, self.mitre, self.registry)


class ShadowShellSession(asyncssh.SSHServerSession):
    def __init__(self, state: SessionState, llm: OllamaClient, bus: AegisBus,
                 mitre: MITREMapper, registry: HoneytokenRegistry | None):
        self.state = state
        self.llm = llm
        self.bus = bus
        self.mitre = mitre
        self.registry = registry
        self._input = ""

    def connection_made(self, chan):
        self.chan = chan
        chan.set_echo(True)
        chan.write(
            "Ubuntu 22.04.3 LTS prod-db-07 tty1\n\n"
            "Last login: Tue Jun 14 13:37:01 2026 from 10.0.0.23\n"
        )
        self._prompt()

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        return True

    def data_received(self, data, datatype):
        self._input += data.decode(errors="replace")
        if "\n" in self._input:
            cmd = self._input.strip("\r\n").strip()
            self._input = ""
            if cmd:
                asyncio.ensure_future(self._handle_command(cmd))

    def _prompt(self):
        self.chan.write(f"{self.state.user}@prod-db-07:{self.state.cwd}# ")

    async def _handle_command(self, cmd: str):
        self.state.commands.append(cmd)
        ttp = self.mitre.classify(cmd)
        if ttp:
            self.bus.emit_honey_cmd(cmd, ttp, self.state.peer)

        if cmd in KNOWN:
            self.chan.write(KNOWN[cmd](cmd))
        elif cmd.startswith("ls") or cmd.startswith("dir"):
            self.chan.write("backup.sh  secrets.env  .ssh  db.dump  creds.txt\n")
        elif cmd.startswith("cat ") or cmd.startswith("sudo cat ") or cmd.startswith("head "):
            f = cmd.split()[-1].lstrip("./")
            self.chan.write(self._read_file(f))
        elif cmd in ("exit", "logout", "Ctrl-D"):
            self.chan.write("logout\n")
            self.chan.close()
            return
        else:
            try:
                out = await self.llm.generate_shell_output(cmd, self.state)
                self.chan.write(out)
            except Exception as e:
                log.warning("LLM error: %s", e)
                self.chan.write(f"bash: {cmd}: command not found\n")
        self._prompt()

    def _read_file(self, f: str) -> str:
        """Чтение из фейковой ФС контейнера + детект утечки honeytoken'а."""
        content = f"cat: {f}: No such file or directory\n"
        if self.state.honeypot_fs is not None:
            for rel in self.state.honeypot_fs.rglob(f):
                if rel.is_file():
                    content = rel.read_text(errors="replace") + "\n"
                    break
        # Honeywatermark: если в выводе есть сгенерированные токены — алерт
        if self.registry:
            hits = self.registry.detect_in_body(content)
            for h in hits:
                self.bus.emit_anomaly(
                    "T1552.001", severity="HIGH",
                    context={"honeytoken": h["kind"], "campaign": h["campaign_id"],
                             "path": f, "src_ip": self.state.peer},
                )
                log.warning("[%s] HONEYTOKEN %s EXPOSED via %s", self.state.peer, h["kind"], f)
        return content


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--http-listen", default="0.0.0.0:8081", help="HTTP API (ApexCore integration)")
    ap.add_argument("--ollama", default="http://127.0.0.1:11434")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--docker", action="store_true", help="enable container orchestration")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO)

    bus = AegisBus()
    mitre = MITREMapper()
    llm = OllamaClient(args.ollama, args.model)
    orch = DockerOrchestrator() if args.docker else None
    registry = HoneytokenRegistry(Path("state/honeytokens.json")) if args.docker else None

    # HTTP API для ApexCore (spawn honeypot / status / metrics).
    api_host, api_port = args.http_listen.rsplit(":", 1)
    await run_api(ShadowNetAPI(bus, orch, registry), api_host, int(api_port))

    # host-ключ SSH: генерируем, если отсутствует (первый запуск).
    host_key_path = Path("host_rsa.key")
    if not host_key_path.exists():
        key = asyncssh.generate_private_key("ssh-rsa")
        host_key_path.write_bytes(key.export_private_key())
        log.info("generated new SSH host key: %s", host_key_path)

    await asyncssh.create_server(
        lambda: ShadowSSHServer(bus, mitre, llm, orch, registry),
        host=args.host,
        port=args.port,
        server_host_keys=[str(host_key_path)],
    )
    log.info("ShadowNet SSH honeypot listening on %s:%d (docker=%s)",
             args.host, args.port, bool(args.docker))
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
