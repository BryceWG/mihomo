#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_BINARY="${REPO_ROOT}/bin/mihomo-darwin-arm64"
DEST_BINARY="/Applications/Sparkle.app/Contents/Resources/sidecar/mihomo-alpha"
CREATE_BACKUP=1

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Replace Sparkle's sidecar mihomo-alpha binary with a freshly built mihomo.

Options:
  -b, --binary PATH    Source binary to install
                       default: ${SOURCE_BINARY}
  -d, --dest PATH      Destination mihomo-alpha path
                       default: ${DEST_BINARY}
      --no-backup      Do not create a timestamped backup first
  -h, --help           Show this help

Examples:
  scripts/$(basename "$0")
  sudo scripts/$(basename "$0")
  scripts/$(basename "$0") --binary ./bin/mihomo-darwin-arm64
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--binary)
      SOURCE_BINARY="$2"
      shift 2
      ;;
    -d|--dest)
      DEST_BINARY="$2"
      shift 2
      ;;
    --no-backup)
      CREATE_BACKUP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "${SOURCE_BINARY}" ]]; then
  echo "Source binary not found: ${SOURCE_BINARY}" >&2
  echo "Build it first with: make darwin-arm64" >&2
  exit 1
fi

DEST_DIR="$(dirname "${DEST_BINARY}")"
DEST_NAME="$(basename "${DEST_BINARY}")"

if [[ ! -d "${DEST_DIR}" ]]; then
  echo "Destination directory not found: ${DEST_DIR}" >&2
  exit 1
fi

if [[ ! -w "${DEST_DIR}" ]]; then
  echo "Destination is not writable: ${DEST_DIR}" >&2
  echo "Try running this script with sudo." >&2
  exit 1
fi

if [[ "${CREATE_BACKUP}" -eq 1 && -e "${DEST_BINARY}" ]]; then
  BACKUP_PATH="${DEST_BINARY}.backup.$(date +%Y%m%d-%H%M%S)"
  cp -p "${DEST_BINARY}" "${BACKUP_PATH}"
  echo "Backup created: ${BACKUP_PATH}"
fi

TMP_PATH="${DEST_DIR}/.${DEST_NAME}.tmp.$$"
cleanup() {
  rm -f "${TMP_PATH}"
}
trap cleanup EXIT

cp "${SOURCE_BINARY}" "${TMP_PATH}"
chmod 0755 "${TMP_PATH}"
xattr -d com.apple.quarantine "${TMP_PATH}" 2>/dev/null || true
mv "${TMP_PATH}" "${DEST_BINARY}"
trap - EXIT

echo "Installed: ${SOURCE_BINARY} -> ${DEST_BINARY}"
