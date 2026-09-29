#!/usr/bin/env bash
# Matched-pair benchmark: same real encrypt/decrypt work, clean/smudge vs the long-running
# filter.process protocol. Both arms MUST exercise real crypto - a no-op filter cannot be a
# process filter (it has to speak pkt-line), so comparing a no-op against a process filter
# would measure different work and produce a flattering, meaningless ratio.
set -euo pipefail

usage() {
    echo "Usage: $0 <clean-smudge|process> [nfiles]" >&2
    exit 1
}

MODE="${1:-}"
NFILES="${2:-20}"

case "$MODE" in
    clean-smudge|process) ;;
    *) usage ;;
esac

CLI="${GIT_SECRET_PROTECTOR_CLI:-git-secret-protector}"

if ! command -v "$CLI" >/dev/null 2>&1; then
    echo "error: '$CLI' not found on PATH. Install it or set GIT_SECRET_PROTECTOR_CLI." >&2
    exit 1
fi

if [ "$MODE" = "process" ]; then
    if ! "$CLI" filter-process --help >/dev/null 2>&1; then
        echo "error: '$CLI filter-process' is not available yet. This benchmark arm needs wave 2's subcommand; refusing to report a bogus number." >&2
        exit 1
    fi
fi

WORKDIR="$(mktemp -d)"
cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

FILTER_NAME="bench-filter"

(
    cd "$WORKDIR"
    git init -q
    git config user.email "bench@example.com"
    git config user.name "bench"

    echo "*.secret filter=$FILTER_NAME" > .gitattributes

    mkdir -p .git_secret_protector/cache .git_secret_protector/logs
    cat > .git_secret_protector/config.ini <<EOF
[DEFAULT]
module_name = git-secret-protector
storage_type = AWS_SSM
encryption_scheme = v2
log_level = WARN
EOF

    # Cache the key/iv locally so encrypt/decrypt run cache-only, no cloud backend touched -
    # this is a spawn-cost benchmark, not a storage-backend benchmark.
    python3 - "$FILTER_NAME" <<'PYEOF'
import base64
import json
import os
import sys

filter_name = sys.argv[1]
data = {
    "aes_key": base64.b64encode(os.urandom(32)).decode("ascii"),
    "iv": base64.b64encode(os.urandom(16)).decode("ascii"),
    "version": 2,
}
path = os.path.join(".git_secret_protector", "cache", f"{filter_name}_key_iv.json")
with open(path, "w") as f:
    f.write(json.dumps(data))
PYEOF

    if [ "$MODE" = "clean-smudge" ]; then
        git config "filter.${FILTER_NAME}.clean" "$CLI encrypt %f"
        git config "filter.${FILTER_NAME}.smudge" "$CLI decrypt %f"
    else
        git config "filter.${FILTER_NAME}.process" "$CLI filter-process ${FILTER_NAME}"
    fi
    git config "filter.${FILTER_NAME}.required" "true"

    for i in $(seq 1 "$NFILES"); do
        head -c 2048 /dev/urandom | base64 > "file${i}.secret"
    done

    git add -A
    git commit -q -m "bench: ${NFILES} files"

    rm -f ./*.secret

    START=$(python3 -c 'import time; print(time.time())')
    git checkout -- .
    END=$(python3 -c 'import time; print(time.time())')

    python3 -c "
total = $END - $START
nfiles = $NFILES
print(f'${MODE}: {total:.3f}s for a {nfiles}-file checkout ({(total / nfiles) * 1000:.1f}ms/file)')
"
)
