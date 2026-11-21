#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tf-sim-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

trim() {
  printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

append_github_path() {
  local dir_native
  dir_native="$(to_native_path "$1")"
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$dir_native" >> "$GITHUB_PATH"
  fi
}

write_github_output() {
  local key="$1"
  local val="$2"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$key" "$val" >> "$GITHUB_OUTPUT"
  fi
}

detect_os() {
  local raw lower
  raw="$(trim "${TFSIM_OS_OVERRIDE:-${RUNNER_OS:-$(uname -s)}}")"
  lower="$(to_lower "$raw")"
  case "$lower" in
    linux*)
      printf 'linux'
      ;;
    darwin*|macos*)
      printf 'darwin'
      ;;
    windows*|mingw*|msys*|cygwin*)
      printf 'windows'
      ;;
    *)
      echo "Error: unsupported operating system '$raw'" >&2
      return 1
      ;;
  esac
}

normalize_arch() {
  local raw lower
  raw="$(trim "$1")"
  lower="$(to_lower "$raw")"
  case "$lower" in
    amd64|x86_64|x64)
      printf 'amd64'
      ;;
    arm64|aarch64)
      printf 'arm64'
      ;;
    *)
      return 1
      ;;
  esac
}

detect_arch() {
  local raw uname_s uname_m
  if [ -n "$(trim "${TFSIM_ARCH_OVERRIDE:-}")" ]; then
    raw="$(trim "$TFSIM_ARCH_OVERRIDE")"
    if ! normalize_arch "$raw"; then
      echo "Error: unsupported TFSIM_ARCH_OVERRIDE '$raw'" >&2
      return 1
    fi
    return 0
  fi

  if [ -n "$(trim "${RUNNER_ARCH:-}")" ]; then
    raw="$(trim "$RUNNER_ARCH")"
    if ! normalize_arch "$raw"; then
      echo "Error: unsupported RUNNER_ARCH '$raw'" >&2
      return 1
    fi
    return 0
  fi

  uname_s="$(to_lower "$(uname -s)")"
  case "$uname_s" in
    *-arm64*)
      printf 'arm64'
      return 0
      ;;
  esac

  uname_m="$(uname -m)"
  if ! normalize_arch "$uname_m"; then
    echo "Error: unsupported architecture '$uname_m' (uname -s: '$uname_s')" >&2
    return 1
  fi
}

OS="$(detect_os)" || exit 2
ARCH="$(detect_arch)" || exit 2

if [ "$OS" = "windows" ]; then
  EXT="zip"
  BIN_NAME="tf-sim.exe"
else
  EXT="tar.gz"
  BIN_NAME="tf-sim"
fi

if [ -n "$(trim "${TFSIM_INSTALL_DIR:-}")" ]; then
  INSTALL_DIR="$(trim "$TFSIM_INSTALL_DIR")"
  mkdir -p "$INSTALL_DIR"
else
  INSTALL_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tf-sim-bin.XXXXXX")"
fi
DEST_BIN="$INSTALL_DIR/$BIN_NAME"

BINARY_PATH_INPUT="$(trim "${INPUT_BINARY_PATH:-}")"
if [ -n "$BINARY_PATH_INPUT" ]; then
  if [ ! -f "$BINARY_PATH_INPUT" ]; then
    echo "Error: binary-path does not exist or is not a regular file: $BINARY_PATH_INPUT" >&2
    exit 2
  fi

  SRC_ABS="$(cd -- "$(dirname -- "$BINARY_PATH_INPUT")" && pwd)/$(basename -- "$BINARY_PATH_INPUT")"
  DEST_ABS="$(cd -- "$INSTALL_DIR" && pwd)/$BIN_NAME"
  if [ "$SRC_ABS" != "$DEST_ABS" ]; then
    if [ -L "$DEST_BIN" ]; then
      echo "Error: destination binary path is a symlink: $DEST_BIN" >&2
      exit 2
    fi
    cp -f -- "$BINARY_PATH_INPUT" "$DEST_BIN"
  fi
  chmod 0755 "$DEST_BIN"
  append_github_path "$INSTALL_DIR"
  write_github_output "binary-path" "$(to_native_path "$DEST_BIN")"
  "$DEST_BIN" --version
  exit 0
fi

VERSION_INPUT="${INPUT_VERSION:-latest}"
if [ -z "$VERSION_INPUT" ]; then
  VERSION_INPUT="latest"
fi

VERSION_REGEX='^(latest|v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$'
if [[ "$VERSION_INPUT" == *".."* ]] || [[ ! "$VERSION_INPUT" =~ $VERSION_REGEX ]]; then
  echo "Error: invalid version '$VERSION_INPUT': expected 'latest' or semver (e.g. v0.1.0)" >&2
  exit 2
fi

if [ "$VERSION_INPUT" = "latest" ]; then
  API_BASE="${TFSIM_API_BASE_URL:-https://api.github.com}"
  API_BASE="${API_BASE%/}"
  RELEASE_REPO="${TFSIM_RELEASE_REPO:-justr00t/tf-sim}"
  API_URL="${API_BASE}/repos/${RELEASE_REPO}/releases/latest"

  CURL_ARGS=(-fsSL --retry 3 -H "Accept: application/vnd.github+json")
  if [[ "$API_URL" == https://api.github.com/* ]] && [ -n "${GITHUB_TOKEN:-}" ]; then
    CURL_CFG="$TMP_DIR/curl-auth.cfg"
    (
      umask 077
      TOKEN_CLEAN="${GITHUB_TOKEN//$'\r'/}"
      TOKEN_CLEAN="${TOKEN_CLEAN//$'\n'/}"
      TOKEN_ESCAPED="${TOKEN_CLEAN//\\/\\\\}"
      TOKEN_ESCAPED="${TOKEN_ESCAPED//\"/\\\"}"
      printf 'header = "Authorization: Bearer %s"\n' "$TOKEN_ESCAPED" > "$CURL_CFG"
    )
    chmod 0600 "$CURL_CFG"
    CURL_ARGS+=(-K "$(to_native_path "$CURL_CFG")")
  fi

  if ! curl "${CURL_ARGS[@]}" "$API_URL" -o "$TMP_DIR/release.json"; then
    echo "Error: failed to query latest release metadata from $API_URL" >&2
    exit 2
  fi

  RESOLVED_VERSION="$(node -e '
    const fs = require("fs");
    const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(String(data.tag_name || ""));
  ' "$(to_native_path "$TMP_DIR/release.json")")"

  TAG_REGEX='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
  if [[ "$RESOLVED_VERSION" == *".."* ]] || [[ ! "$RESOLVED_VERSION" =~ $TAG_REGEX ]]; then
    echo "Error: invalid tag_name '$RESOLVED_VERSION' returned by $API_URL" >&2
    exit 2
  fi
else
  RESOLVED_VERSION="$VERSION_INPUT"
fi

TAG="v${RESOLVED_VERSION#v}"
VER_NUM="${TAG#v}"
ARCHIVE="tf-sim_${VER_NUM}_${OS}_${ARCH}.${EXT}"

RELEASE_REPO="${TFSIM_RELEASE_REPO:-justr00t/tf-sim}"
BASE_URL="${TFSIM_RELEASE_BASE_URL:-https://github.com/${RELEASE_REPO}/releases/download}"
BASE_URL="${BASE_URL%/}"

ARCHIVE_URL="${BASE_URL}/${TAG}/${ARCHIVE}"
CHECKSUMS_URL="${BASE_URL}/${TAG}/checksums.txt"

if ! curl -fsSL --retry 3 "$ARCHIVE_URL" -o "$TMP_DIR/$ARCHIVE"; then
  echo "Error: failed to download release archive from $ARCHIVE_URL" >&2
  exit 2
fi

if ! curl -fsSL --retry 3 "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt"; then
  echo "Error: failed to download checksums manifest from $CHECKSUMS_URL" >&2
  exit 2
fi

EXPECTED_HASH="$(tr -d '\r' < "$TMP_DIR/checksums.txt" | awk -v f="$ARCHIVE" '$2 == f || $2 == "*"f { print tolower($1); exit }')"
HASH_REGEX='^[0-9a-f]{64}$'
if [[ ! "$EXPECTED_HASH" =~ $HASH_REGEX ]]; then
  echo "Error: valid SHA256 entry for '$ARCHIVE' not found in checksums.txt" >&2
  exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print tolower($1)}')"
else
  ACTUAL_HASH="$(node -e '
    const fs = require("fs");
    const crypto = require("crypto");
    const hash = crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex");
    process.stdout.write(hash.toLowerCase());
  ' "$(to_native_path "$TMP_DIR/$ARCHIVE")")"
fi

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  echo "Error: SHA256 checksum mismatch for $ARCHIVE (expected: $EXPECTED_HASH, actual: $ACTUAL_HASH)" >&2
  rm -f "$TMP_DIR/$ARCHIVE"
  exit 2
fi

mkdir -p "$TMP_DIR/extracted"
if [ "$EXT" = "zip" ]; then
  ARCHIVE_LIST="$(unzip -Z1 "$TMP_DIR/$ARCHIVE" | tr -d '\r')"
else
  ARCHIVE_LIST="$(tar -tzf "$TMP_DIR/$ARCHIVE" | tr -d '\r')"
fi

TARGET_ENTRY=""
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  if [[ "$entry" == /* ]] || [[ "$entry" == \\* ]] || [[ "$entry" =~ ^[A-Za-z]: ]] || [[ "$entry" == ".." ]] || [[ "$entry" == ../* ]] || [[ "$entry" == */.. ]] || [[ "$entry" == */../* ]]; then
    echo "Error: unsafe path entry '$entry' detected inside $ARCHIVE" >&2
    exit 2
  fi
  if [ "$entry" = "$BIN_NAME" ] || [ "$entry" = "./$BIN_NAME" ]; then
    TARGET_ENTRY="$entry"
  fi
done <<< "$ARCHIVE_LIST"

if [ -z "$TARGET_ENTRY" ]; then
  echo "Error: expected binary '$BIN_NAME' not found inside $ARCHIVE" >&2
  exit 2
fi

if [ "$EXT" = "zip" ]; then
  unzip -q "$TMP_DIR/$ARCHIVE" "$TARGET_ENTRY" -d "$TMP_DIR/extracted"
else
  tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR/extracted" -- "$TARGET_ENTRY"
fi

if [ -L "$TMP_DIR/extracted/$BIN_NAME" ] || [ ! -f "$TMP_DIR/extracted/$BIN_NAME" ]; then
  echo "Error: extracted binary '$BIN_NAME' is missing or is a symlink inside $ARCHIVE" >&2
  exit 2
fi

if [ -L "$DEST_BIN" ]; then
  echo "Error: destination binary path is a symlink: $DEST_BIN" >&2
  exit 2
fi

cp -f -- "$TMP_DIR/extracted/$BIN_NAME" "$DEST_BIN"
chmod 0755 "$DEST_BIN"

append_github_path "$INSTALL_DIR"
write_github_output "binary-path" "$(to_native_path "$DEST_BIN")"

"$DEST_BIN" --version
