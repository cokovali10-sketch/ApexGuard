#!/usr/bin/env python3
# ShadowNet — Honeytokens (HoneyTokens) generator + Watermarking.
#
# Генерирует правдоподобные фальшивые секреты с уникальным watermark'ом:
#   AWS_SECRET_KEY, DB_PASSWORD, API keys, SSH private key, .git/ каталог.
# Каждый токен содержит campaign_id (внедрённый канал) — при «утечке» токена
# за пределы honeypot'а аналитик определяет канал (фильтр-канал) по watermarк'у.
#
# Регистрация: SHA-256(token) → metadata. Хранится в Redis (рекомендуется)
# либо в memmap-файле; детекция срабатывания — по появлению хэша в потоках
# данных (Dark Web Monitor / SIEM / можноринг десепшн-аналитикой).
import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
# --- константы вынесены FORGE refactor ---
CONST_8 = 8
CONST_16 = 16
CONST_64 = 64
CONST_400 = 400


# ---------------------------------------------------------------------------
# Детерминированная генерация «правдоподобных» секретов
# ---------------------------------------------------------------------------
ALPHANUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz0123456789"
HEX = "0123456789abcdef"

def _rnd(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass
class Honeytoken:
    kind: str            # aws_secret, db_password, api_key, ssh_key, jwt
    value: str           # сам токен
    campaign_id: str     # watermark-канал (внедряется в токен)
    fingerprint: str     # sha256(value)
    inserted_path: str   # файл, в котором лежит
    created_at: str


class HoneytokenGenerator:
    def __init__(self, campaign_id: str | None = None, embed_secret: str | None = None):
        """embed_secret — HMAC-ключ watermark'а (секрет платформы)."""
        self.campaign = campaign_id or f"camp-{uuid.uuid4().hex[:CONST_8]}"
        self.embed_secret = embed_secret or os.environ.get("APEX_HONEY_HMAC", "apex-default")

    # -- примитивы -----------------------------------------------------
    def _watermark(self) -> str:
        """Уникальный маркер канала: предсказуем для аналитика, неочевиден для атакующего."""
        return f"wmk-{self.campaign}-{secrets.token_hex(4)}"

    def _aws_secret(self) -> str:
        return "AKIA" + _rnd(ALPHANUM, CONST_16)  # заглушка-access key + секрет ниже

    def _aws_secret_key(self) -> str:
        return _rnd(ALPHANUM + "+/=", 40)

    def _db_password(self) -> str:
        return _rnd(ALPHANUM, 24) + "!"

    def _api_key(self) -> str:
        return "sk_live_" + _rnd(ALPHANUM + "-", 32)

    def _ssh_private_key(self, comment: str = "prod-deploy") -> str:
        # Достаточно правдоподобная структура (не реальный ключ).
        body = base64.b64encode(secrets.token_bytes(CONST_400)).decode()
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + "\n".join(body[i:i + CONST_64] for i in range(0, len(body), CONST_64))
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        )

    def _jwt(self) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "deploy-bot", "role": "ci", "scope": "deploy:prod"}).encode()
        ).rstrip(b"=").decode()
        sig = hmac.new(self.embed_secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        return f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

    # -- композиция (с внедрённым watermark'ом) --------------------------
    def make(self, kind: str) -> Honeytoken:
        wm = self._watermark()
        value = {
            "aws_access_key": self._aws_secret(),
            "aws_secret_key": self._aws_secret_key() + wm[-12:],  # watermark в конце
            "db_password": self._db_password(),
            "api_key": self._api_key(),
            "ssh_key": self._ssh_private_key(),
            "jwt": self._jwt(),
        }[kind]
        if kind in ("db_password", "api_key"):
            # watermark как «соль» в середине
            value = value[:CONST_8] + wm.replace("-", "_")[:CONST_16] + value[CONST_8:]
        fp = hashlib.sha256(value.encode()).hexdigest()
        return Honeytoken(
            kind=kind, value=value, campaign_id=self.campaign,
            fingerprint=fp, inserted_path="", created_at=str(uuid.uuid4()),
        )


# ---------------------------------------------------------------------------
# Внедрение в фейковую ФС honeypot-контейнера
# ---------------------------------------------------------------------------
class FakeFSBuilder:
    """Строит дерево фейковой ФС + .git каталог + регистрацию токенов."""

    def __init__(self, root: Path, generator: HoneytokenGenerator):
        self.root = root
        self.gen = generator
        self.tokens: list[Honeytoken] = []

    def build(self) -> list[Honeytoken]:
        r = self.root
        (r / "opt/backup").mkdir(parents=True, exist_ok=True)
        (r / "etc").mkdir(parents=True, exist_ok=True)
        (r / "var/www/html").mkdir(parents=True, exist_ok=True)
        (r / "home/deploy/.ssh").mkdir(parents=True, exist_ok=True)
        (r / "srv/git/backend").mkdir(parents=True, exist_ok=True)

        # 1. secrets.env
        aws_key = self.gen.make("aws_access_key")
        aws_secret = self.gen.make("aws_secret_key")
        db_pass = self.gen.make("db_password")
        api = self.gen.make("api_key")
        env = (
            f"AWS_ACCESS_KEY_ID={aws_key.value}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_secret.value}\n"
            f"DB_PASSWORD={db_pass.value}\n"
            f"PAYMENTS_API_KEY={api.value}\n"
            f"JWT_SECRET={self.gen.make('jwt').value}\n"
        )
        self._write("opt/backup/secrets.env", env, [aws_key, aws_secret, db_pass, api])

        # 2. SSH ключ деплоя
        ssh = self.gen.make("ssh_key")
        self._write("home/deploy/.ssh/id_rsa", ssh.value, [ssh])

        # 3. .git каталог — «незакоммиченные» секреты
        git = r / "srv/git/backend/.git"
        (git / "objects").mkdir(parents=True, exist_ok=True)
        (git / "refs/heads").mkdir(parents=True, exist_ok=True)
        (git / "config").write_text("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/backend.git\n")
        (git / "HEAD").write_text("ref: refs/heads/main\n")
        (git / "logs").mkdir(parents=True, exist_ok=True)
        (r / "srv/git/backend/.env.production").write_text(f"STRIPE_SECRET={api.value}\n")

        # 4. бэкап-файлы
        (r / "opt/backup/db.dump").write_text(
            "COPY public.users (id, email, password_hash) FROM stdin;\n"
            f"1\tadmin@corp.local\t{db_pass.value}\n"
        )
        (r / "opt/backup/backup.sh").write_text(
            f"#!/bin/sh\nAWS_SECRET_KEY={aws_secret.value} mysqldump -u root -p{db_pass.value} --all-databases\n"
        )

        # 5. веб-креды
        (r / "var/www/html/wp-config.php").write_text(
            "define('DB_PASSWORD', '" + db_pass.value + "');\n"
        )
        return self.tokens

    def _write(self, rel: str, content: str, tokens: list[Honeytoken]) -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        for t in tokens:
            t.inserted_path = rel
            self.tokens.append(t)

    def fingerprint_manifest(self) -> str:
        return json.dumps([asdict(t) for t in self.tokens], indent=2)


# ---------------------------------------------------------------------------
# Реестр и детекция срабатывания
# ---------------------------------------------------------------------------
class HoneytokenRegistry:
    """SHA-256 → metadata. Появление fingerprint'а во внешних данных = утечка."""

    def __init__(self, state_file: Path):
        self.state_file = state_file
        self._by_fp: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.state_file.exists():
            for entry in json.loads(self.state_file.read_text()):
                self._by_fp[entry["fingerprint"]] = entry

    def register(self, tokens: list[Honeytoken]) -> None:
        for t in tokens:
            self._by_fp[t.fingerprint] = asdict(t)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(list(self._by_fp.values()), indent=2))

    def fingerprint(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def check_exposure(self, text: str) -> dict | None:
        """Возвращает токен, если текст содержит его значение (для канареечных проверок)."""
        h = self.fingerprint(text)
        return self._by_fp.get(h)

    def detect_in_body(self, body: str) -> list[dict]:
        """Поиск точных значений токенов в произвольном теле (например, в собранном логин-выводе)."""
        hits = []
        for fp, meta in self._by_fp.items():
            if meta["value"] in body:
                hits.append(meta)
        return hits


if __name__ == "__main__":
    import tempfile

    gen = HoneytokenGenerator(campaign_id="demo")
    root = Path(tempfile.mkdtemp(prefix="fakefs-"))
    fs = FakeFSBuilder(root, gen)
    tokens = fs.build()
    reg = HoneytokenRegistry(root / "registry.json")
    reg.register(tokens)
    print(f"root={root}")
    print(f"tokens={len(tokens)}")
    for t in tokens:
        print(" ", t.kind, t.fingerprint[:CONST_16], "->", t.inserted_path)
    print(fs.fingerprint_manifest()[:CONST_400])
