#!/bin/bash
#
# Deploy stepsecurity-dev-machine-guard.exe to a remote Windows machine.
#
# Builds the Windows binary, copies it via SCP, and optionally runs a scan.
# Requires: go, sshpass (for password auth) or SSH key-based auth.
#
# Usage:
#   ./scripts/deploy-windows.sh --host HOST --user USER [OPTIONS]
#
# Examples:
#   # Password auth (prompted or via env)
#   DEPLOY_PASSWORD='secret' ./scripts/deploy-windows.sh --host 10.0.0.5 --user Administrator
#
#   # SSH key auth
#   ./scripts/deploy-windows.sh --host 10.0.0.5 --user Administrator --key ~/.ssh/id_rsa
#
#   # Deploy + run scan
#   ./scripts/deploy-windows.sh --host 10.0.0.5 --user Administrator --run
#
#   # Skip build (binary already exists)
#   ./scripts/deploy-windows.sh --host 10.0.0.5 --user Administrator --no-build
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_NAME="stepsecurity-dev-machine-guard.exe"
REMOTE_DIR=""  # resolved after USER is set

# Defaults
HOST=""
USER=""
KEY=""
PASSWORD="${DEPLOY_PASSWORD:-}"
DO_BUILD=true
DO_RUN=false
RUN_ARGS=""
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

usage() {
    cat <<EOF
Usage: $(basename "$0") --host HOST --user USER [OPTIONS]

Required:
  --host HOST         Remote Windows machine IP or hostname
  --user USER         SSH username (e.g., Administrator)

Authentication (one of):
  --key FILE          SSH private key file
  DEPLOY_PASSWORD     Environment variable with SSH password (uses sshpass)

Options:
  --no-build          Skip build step (use existing .exe)
  --run [ARGS]        Run a scan after deploying (pass extra flags after --)
  --remote-dir DIR    Remote directory (default: C:\\Users\\<USER>)
  -h, --help          Show this help

Examples:
  DEPLOY_PASSWORD='pw' $0 --host 10.0.0.5 --user Admin
  $0 --host 10.0.0.5 --user Admin --key ~/.ssh/id_rsa --run
  $0 --host 10.0.0.5 --user Admin --run -- --enable-npm-scan --json
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       HOST="$2"; shift 2 ;;
        --user)       USER="$2"; shift 2 ;;
        --key)        KEY="$2"; shift 2 ;;
        --no-build)   DO_BUILD=false; shift ;;
        --run)        DO_RUN=true; shift ;;
        --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
        -h|--help)    usage ;;
        --)           shift; RUN_ARGS="$*"; break ;;
        *)            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Validate required args
if [[ -z "$HOST" || -z "$USER" ]]; then
    echo "Error: --host and --user are required" >&2
    echo "Run with --help for usage" >&2
    exit 1
fi

# Resolve default remote directory using the SSH user
if [[ -z "$REMOTE_DIR" ]]; then
    REMOTE_DIR="C:\\Users\\${USER}"
fi

# Build SSH/SCP command prefix based on auth method
ssh_cmd() {
    if [[ -n "$KEY" ]]; then
        ssh $SSH_OPTS -i "$KEY" "${USER}@${HOST}" "$@"
    elif [[ -n "$PASSWORD" ]]; then
        if ! command -v sshpass &>/dev/null; then
            echo "Error: sshpass required for password auth (brew install sshpass / apt install sshpass)" >&2
            exit 1
        fi
        SSHPASS="$PASSWORD" sshpass -e ssh $SSH_OPTS "${USER}@${HOST}" "$@"
    else
        echo "Error: provide --key or set DEPLOY_PASSWORD" >&2
        exit 1
    fi
}

scp_cmd() {
    local src="$1" dst="$2"
    if [[ -n "$KEY" ]]; then
        scp $SSH_OPTS -i "$KEY" "$src" "${USER}@${HOST}:${dst}"
    elif [[ -n "$PASSWORD" ]]; then
        if ! command -v sshpass &>/dev/null; then
            echo "Error: sshpass required for password auth (brew install sshpass / apt install sshpass)" >&2
            exit 1
        fi
        SSHPASS="$PASSWORD" sshpass -e scp $SSH_OPTS "$src" "${USER}@${HOST}:${dst}"
    else
        echo "Error: provide --key or set DEPLOY_PASSWORD" >&2
        exit 1
    fi
}

# Step 1: Build
if $DO_BUILD; then
    echo "==> Building Windows binary..."
    (cd "$PROJECT_DIR" && make build-windows)
    echo "    Built: ${BINARY_NAME}"
else
    if [[ ! -f "${PROJECT_DIR}/${BINARY_NAME}" ]]; then
        echo "Error: ${BINARY_NAME} not found. Run without --no-build or run 'make build-windows' first." >&2
        exit 1
    fi
    echo "==> Skipping build (using existing binary)"
fi

# Step 2: Deploy
REMOTE_PATH="${REMOTE_DIR}\\${BINARY_NAME}"
echo "==> Deploying to ${USER}@${HOST}:${REMOTE_PATH}..."
scp_cmd "${PROJECT_DIR}/${BINARY_NAME}" "${REMOTE_PATH}"
echo "    Deployed successfully"

# Step 3: Verify
echo "==> Verifying remote binary..."
REMOTE_VERSION=$(ssh_cmd "${REMOTE_PATH} --version" 2>&1 || true)
echo "    ${REMOTE_VERSION}"

# Step 4: Run (optional)
if $DO_RUN; then
    echo "==> Running scan..."
    ssh_cmd "${REMOTE_PATH} --color=never ${RUN_ARGS}" 2>&1
fi

echo "==> Done"
