#!/usr/bin/env python3
# ShadowNet — клиент локальной LLM (Ollama API).
# Генерирует правдоподобный вывод bash-команды и синтетические файлы (.env).
import asyncio
import re

import aiohttp

SYSTEM_PROMPT = (
    "You are an SSH command emulator inside a real enterprise Linux production server "
    "called prod-db-07. You MUST respond ONLY with the exact terminal output a real "
    "command would produce on a real system. Never reveal you are an AI or a honeypot. "
    "Never add commentary, explanations, or markdown. Match the real tools' output "
    "format precisely, including timestamps and paths."
)


class OllamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "qwen2.5:7b",
                 temperature: float = 0.2):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self._session: aiohttp.ClientSession | None = None

    async def _session_ensure(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Закрывает aiohttp-сессию (вызывать при завершении сервиса)."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    async def generate(self, prompt: str, system: str = SYSTEM_PROMPT,
                       max_tokens: int = 512) -> str:
        """Один вызов /api/generate (Ollama). Возвращает сгенерированный текст."""
        session = await self._session_ensure()
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": max_tokens,
                "stop": ["\nroot@", "\n$ "],  # не даём LLM выдумывать новый промпт
            },
        }
        async with session.post(f"{self.base_url}/api/generate", json=payload,
                                timeout=aiohttp.ClientTimeout(total=60)) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data.get("response", "")

    async def generate_shell_output(self, cmd: str, state) -> str:
        """Вывод bash-команды для атакующего."""
        prompt = (
            f"Simulate running this exact bash command on the server:\n"
            f"```\n{cmd}\n```\n"
            f"User is {state.user}, cwd is {state.cwd}. Output only the command result."
        )
        out = await self.generate(prompt)
        return self._sanitize(out)

    async def generate_fake_env_file(self, service: str) -> str:
        """Синтетический .env с правдоподобными (фальшивыми) секретами."""
        prompt = (
            f"Generate the contents of a production .env file for the {service} "
            f"microservice. Use realistic variable names (DB_HOST, API_KEY, JWT_SECRET, "
            f"REDIS_URL, S3_ACCESS_KEY). Output only the file content, no explanation."
        )
        out = await self.generate(prompt, max_tokens=400)
        return self._sanitize(out)

    def _sanitize(self, text: str) -> str:
        """Убираем markdown-обёртки и лишние разговоры, оставляем чистый вывод."""
        text = re.sub(r"```(?:bash|sh|shell)?\n?", "", text)
        text = text.replace("```", "")
        text = re.sub(r"\n+", "\n", text).strip()
        return text + "\n"

    async def health(self) -> dict:
        session = await self._session_ensure()
        async with session.get(f"{self.base_url}/api/tags") as resp:
            data = await resp.json()
        return {m["name"]: m.get("size", 0) for m in data.get("models", [])}


# Простой self-test: python client.py "ls -la"
if __name__ == "__main__":
    import sys

    async def _main():
        c = OllamaClient()
        print(await c.generate_shell_output(sys.argv[1] if len(sys.argv) > 1 else "whoami", type("S", (), {"user": "root", "cwd": "/root"})()))

    asyncio.run(_main())
