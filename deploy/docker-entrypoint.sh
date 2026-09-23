#!/bin/sh
set -e

# Fix data directory permissions when running as root.
# Docker named volumes / host bind-mounts may be owned by root,
# preventing the non-root sub2api user from writing files.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/data
    # Use || true to avoid failure on read-only mounted files (e.g. config.yaml:ro)
    chown -R sub2api:sub2api /app/data 2>/dev/null || true

    # Stage the root-only Compose secret into tmpfs before dropping privileges.
    reauth_secret=/run/secrets/reauth-keyring.json
    reauth_tmpfs=/run/sub2api-secrets
    if [ -r "$reauth_secret" ]; then
        if [ -d "$reauth_tmpfs" ] && install -o sub2api -g sub2api -m 0400 "$reauth_secret" "$reauth_tmpfs/keyring.json"; then
            export OPENAI_REAUTH_KEYRING_FILE="$reauth_tmpfs/keyring.json"
        else
            echo "Warning: OpenAI reauthorization keyring could not be staged; worker will remain disabled." >&2
            export OPENAI_REAUTH_KEYRING_FILE=
        fi
    fi

    # Re-invoke this script as sub2api so the flag-detection below
    # also runs under the correct user.
    exec su-exec sub2api "$0" "$@"
fi

# Compatibility: if the first arg looks like a flag (e.g. --help),
# prepend the default binary so it behaves the same as the old
# ENTRYPOINT ["/app/sub2api"] style.
if [ "${1#-}" != "$1" ]; then
    set -- /app/sub2api "$@"
fi

exec "$@"
