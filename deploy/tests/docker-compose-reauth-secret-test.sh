#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

python_bin=python3
if ! command -v "$python_bin" >/dev/null 2>&1; then
  python_bin=python
fi
"$python_bin" - <<'PY'
from pathlib import Path

overlay = Path("deploy/docker-compose.reauth.yml").read_text()
entrypoint = Path("deploy/docker-entrypoint.sh").read_text()

required_overlay = (
    "source: openai_reauth_keyring",
    "target: reauth-keyring.json",
    "/run/sub2api-secrets:mode=0700,uid=1000,gid=1000,size=1m",
    "OPENAI_REAUTH_KEYRING_FILE=/run/sub2api-secrets/keyring.json",
    "file: ${OPENAI_REAUTH_KEYRING_HOST_FILE:?Set OPENAI_REAUTH_KEYRING_HOST_FILE to the absolute host keyring path}",
)
for fragment in required_overlay:
    assert fragment in overlay, f"reauth Compose overlay is missing: {fragment}"

required_entrypoint = (
    "reauth_secret=/run/secrets/reauth-keyring.json",
    "install -o sub2api -g sub2api -m 0400",
    "export OPENAI_REAUTH_KEYRING_FILE=",
    "exec su-exec sub2api",
)
for fragment in required_entrypoint:
    assert fragment in entrypoint, f"entrypoint secret staging is missing: {fragment}"

assert "OPENAI_REAUTH_ENABLED=true" not in overlay, \
    "the opt-in overlay must not silently enable automatic reauthorization"
print("docker compose reauth secret static test passed")
PY
