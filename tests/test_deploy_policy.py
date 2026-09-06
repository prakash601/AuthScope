"""T05 policy: secrets are never committed or baked into images.

Pure file-assertion test — no infra needed.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "deploy" / "k8s" / "config-and-secrets.example.yaml"
WORKLOADS = [
    ROOT / "deploy" / "k8s" / "api.yaml",
    ROOT / "deploy" / "k8s" / "worker.yaml",
    ROOT / "deploy" / "k8s" / "migrations-job.yaml",
]
EXPECTED_SECRET_KEYS = {
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
}


def test_example_secrets_are_placeholders_only():
    text = EXAMPLE.read_text()
    assert "replace-me" in text
    secret_doc = text.split("stringData", 1)[1].split("---", 1)[0]
    keys = {
        line.split(":", 1)[0].strip()
        for line in secret_doc.splitlines()
        if ":" in line and line.split(":", 1)[0].strip().isupper()
    }
    assert keys >= EXPECTED_SECRET_KEYS
    for line in secret_doc.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip() in EXPECTED_SECRET_KEYS and "authscope" not in value.lower():
            assert "replace-me" in value, f"{key.strip()} looks like a real value"


def test_images_bake_no_secrets():
    for name in ("Dockerfile.api", "Dockerfile.worker"):
        for line in (ROOT / name).read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            upper = stripped.upper()
            assert not any(
                token in upper for token in ("POSTGRES_PASSWORD", "S3_SECRET_KEY", "S3_ACCESS_KEY")
            ), f"{name}: baked secret? {stripped!r}"


def test_workloads_consume_secretref():
    for path in WORKLOADS:
        text = path.read_text()
        assert "secretRef: { name: authscope-secrets }" in text, path.name
        assert "configMapRef: { name: authscope-config }" in text, path.name


def test_env_file_is_gitignored():
    gitignore = (ROOT / ".gitignore").read_text()
    assert ".env" in gitignore.splitlines()
