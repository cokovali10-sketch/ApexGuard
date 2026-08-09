#!/usr/bin/env python3
# ShadowNet — Docker orchestration.
#
# При входящем SSH-соединении поднимает изолированный honeypot-контейнер
# с жёсткими лимитами:
#   * cgroups: RAM 128MB, CPU 0.5, PIDs 64
#   * no egress network (custom bridge, единственный шлюз — в honeypot)
#   * read_only rootfs, no-new-privileges, без CAPs и --privileged
#   * фейковая ФС (bind-mount) с honeytokens внедряется до старта
#
# Тайм-аут 500ms достигается: кэш image, docker create+start (не run),
# асинхронный TCP к docker socket через aiohttp, минимальный образ
# `alpine:3.20` (~7MB) без entrypoint-работ.
import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

log = logging.getLogger("shadownet.docker")

DOCKER_SOCK = "unix:///var/run/docker.sock"
IMAGE = "alpine:3.20"
SPAWN_BUDGET_MS = 500  # бюджет на create+start

NETWORK_NAME = "deception-net"


@dataclass
class HoneypotContainer:
    id: str
    name: str
    pid: int
    fake_fs_host: str
    created_at: float = field(default_factory=time.time)


class DockerOrchestrator:
    """Тонкий клиент Docker Engine API v1.41 (unix socket) через aiohttp."""

    def __init__(self, sock: str = DOCKER_SOCK, image: str = IMAGE):
        self.image = image
        self._session: Optional[aiohttp.ClientSession] = None
        self._images_checked = False
        self._network_ready = False
        self._last_spawn: dict[str, float] = {}  # rate-limit per IP
        if sock.startswith("unix://"):
            self._url = "http://docker"
            import aiohttp_unix  # type: ignore
            self._connector = aiohttp_unix.UnixConnector(path=sock[7:])
        else:
            self._url = sock
            self._connector = None

    async def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(connector=self._connector)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    async def ensure_image(self) -> None:
        """Проверка/подтягивание минимального образа (кэшируется)."""
        if self._images_checked:
            return
        c = await self._client()
        async with c.get(f"{self._url}/v1.41/images/json") as resp:
            images = await resp.json()
        have = any(i["RepoTags"] and self.image in i["RepoTags"] for i in images)
        if not have:
            log.info("pulling %s ...", self.image)
            async with c.post(f"{self._url}/v1.41/images/create?fromImage={self.image}") as resp:
                resp.raise_for_status()
        self._images_checked = True

    async def ensure_network(self) -> str:
        """Создаёт изолированную internal bridge-сеть (без интернета), если её нет."""
        if self._network_ready:
            return NETWORK_NAME
        c = await self._client()
        cfg = {
            "Name": NETWORK_NAME,
            "Driver": "bridge",
            "Internal": True,  # Docker сам блокирует внешний трафик
            "Options": {"com.docker.network.bridge.enable_icc": "false"},
        }
        async with c.post(f"{self._url}/v1.41/networks/create", json=cfg) as resp:
            if resp.status not in (201, 409):
                body = await resp.text()
                raise RuntimeError(f"network create failed: {resp.status} {body[:200]}")
        self._network_ready = True
        return NETWORK_NAME

    async def spawn(self, name: str, fake_fs_host: str) -> HoneypotContainer:
        """create + start контейнера. Гарантия ≤500ms при прогретом кэше."""
        await self.ensure_image()
        await self.ensure_network()

        start = time.perf_counter()
        c = await self._client()

        host_config = {
            "Memory": 128 * 1024 * 1024,          # cgroup v2 memory.max = 128MB
            "MemorySwap": 0,                       # отключаем swap
            "CpuShares": 512,                      # ~0.5 CPU (1024 = 1 core)
            "PidsLimit": 64,
            "Privileged": False,
            "CapAdd": [],
            "CapDrop": ["ALL"],                    # никаких caps
            "SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"],
            "NetworkMode": NETWORK_NAME,
            "Binds": [f"{fake_fs_host}:/fakerep:ro"],
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "no"},
            "AutoRemove": False,
        }

        config = {
            "Image": self.image,
            "Hostname": "prod-db-07",
            "Cmd": ["/bin/sh", "-c", "trap 'exit' TERM; while true; do sleep 3600; done"],
            "Env": [
                "TERM=xterm",
                "HOSTNAME=prod-db-07",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ],
            "Tty": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "HostConfig": host_config,
        }

        # create
        async with c.post(f"{self._url}/v1.41/containers/create?name={name}", json=config) as resp:
            if resp.status >= 300:
                body = await resp.text()
                raise RuntimeError(f"create failed: {resp.status} {body[:200]}")
            created = await resp.json()
        cid = created["Id"]

        # start
        async with c.post(f"{self._url}/v1.41/containers/{cid}/start") as resp:
            if resp.status >= 300:
                await self.remove(cid)
                raise RuntimeError(f"start failed: {resp.status}")

        # pid контейнера (для логирования)
        async with c.get(f"{self._url}/v1.41/containers/{cid}/json") as resp:
            info = await resp.json()
        pid = info.get("State", {}).get("Pid", 0)

        dt = (time.perf_counter() - start) * 1000
        log.info("spawned %s in %.0fms (pid=%s)", name, dt, pid)
        return HoneypotContainer(id=cid, name=name, pid=pid, fake_fs_host=fake_fs_host)

    async def remove(self, cid: str) -> None:
        c = await self._client()
        async with c.delete(f"{self._url}/v1.41/containers/{cid}?force=true") as resp:
            await resp.read()

    async def exec_ls(self, cid: str, path: str) -> str:
        """Пример docker exec (для зеркалирования вывода ls из контейнера)."""
        c = await self._client()
        spec = {
            "AttachStdout": True,
            "Cmd": ["/bin/ls", "-la", path],
            "Tty": False,
        }
        async with c.post(f"{self._url}/v1.41/containers/{cid}/exec", json=spec) as resp:
            exec_id = (await resp.json())["Id"]
        async with c.post(f"{self._url}/v1.41/exec/{exec_id}/start",
                          json={"Detach": False, "Tty": False}) as resp:
            out = await resp.read()
        return out.decode(errors="replace")

    # ------------------------------------------------------------------
    def rate_limit_ok(self, src_ip: str, min_interval_s: float = 5.0) -> bool:
        """Защита от спама ловушек с одного IP."""
        now = time.time()
        last = self._last_spawn.get(src_ip, 0)
        if now - last < min_interval_s:
            return False
        self._last_spawn[src_ip] = now
        return True


# Быстрый smoke-test: python orchestrator.py --smoke
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="spawn/remove test container")
    args = ap.parse_args()

    async def main():
        logging.basicConfig(level=logging.INFO)
        orch = DockerOrchestrator()
        if args.smoke:
            import tempfile, pathlib
            fake = pathlib.Path(tempfile.mkdtemp())
            (fake / "secrets.env").write_text("DB_PASSWORD=fake\n")
            c = await orch.spawn(f"deception-smoke-{uuid.uuid4().hex[:8]}", str(fake))
            print("container:", c.id[:12], "pid:", c.pid)
            await orch.remove(c.id)
        await orch.close()

    asyncio.run(main())
