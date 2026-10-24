import hashlib
import re
from pathlib import Path


from shadownet.honeytokens.generator import FakeFSBuilder, HoneytokenGenerator, HoneytokenRegistry
# --- константы вынесены FORGE refactor ---
CONST_3 = 3



def test_aws_access_key_format():
    gen = HoneytokenGenerator(campaign_id="t")
    tok = gen.make("aws_access_key")
    assert tok.kind == "aws_access_key"
    assert tok.value.startswith("AKIA")
    assert len(tok.value) == 20
    assert tok.campaign_id == "t"


def test_ssh_key_format():
    gen = HoneytokenGenerator(campaign_id="t")
    tok = gen.make("ssh_key")
    assert tok.value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert tok.value.endswith("-----END OPENSSH PRIVATE KEY-----\n")


def test_jwt_is_verifiable():
    gen = HoneytokenGenerator(campaign_id="t")
    tok = gen.make("jwt")
    parts = tok.value.split(".")
    assert len(parts) == CONST_3
    assert parts[0] and parts[1] and parts[2]


def test_watermark_embedded():
    gen = HoneytokenGenerator(campaign_id="camp-abc")
    db = gen.make("db_password")
    # watermark внедряется в середину значения в underscore-форме
    assert re.search(r"wmk_camp_abc_", db.value)
    # fingerprint must match value
    assert db.fingerprint == hashlib.sha256(db.value.encode()).hexdigest()


def test_fakefs_build_writes_tokens():
    gen = HoneytokenGenerator(campaign_id="t")
    root = Path(__import__("tempfile").mkdtemp())
    fs = FakeFSBuilder(root, gen)
    tokens = fs.build()
    assert len(tokens) > CONST_3
    kinds = {t.kind for t in tokens}
    assert "aws_secret_key" in kinds
    # все файлы реально записаны
    for t in tokens:
        if t.inserted_path:
            assert (root / t.inserted_path.lstrip("/")).exists()


def test_registry_roundtrip_and_exposure(tmp_path):
    gen = HoneytokenGenerator(campaign_id="t")
    tok = gen.make("db_password")
    reg = HoneytokenRegistry(tmp_path / "state" / "registry.json")
    reg.register([tok])

    # повторная загрузка из файла
    reg2 = HoneytokenRegistry(tmp_path / "state" / "registry.json")
    assert reg2.check_exposure(tok.value) is not None

    # произвольный текст — не токен
    assert reg2.check_exposure("plain text") is None

    # обнаружение внутри произвольного тела
    hits = reg2.detect_in_body(f"leaked: {tok.value} leaked!")
    assert len(hits) == 1
    assert hits[0]["kind"] == "db_password"
