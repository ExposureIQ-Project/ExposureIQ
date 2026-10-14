#!/usr/bin/env bash
# ExposureIQ helper: installs what is needed and runs the tool.
#
#   ./run.sh install                 install Subfinder, the Python packages and the
#                                    'exposureiq' command
#   ./run.sh test                    run the tests
#   ./run.sh scan <domain> [options] same as:  exposureiq scan <domain> [options]
#
# After './run.sh install' you can simply type:   exposureiq scan example.com
#   (see 'exposureiq scan --help' for all options)
#
# Only scan domains you own or have permission to test. Finding subdomains only
# reads public data, but port scanning (--ports) sends real traffic.

set -euo pipefail

SUBFINDER_VERSION="${SUBFINDER_VERSION:-2.17.0}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
ORIGINAL_PATH="$PATH"
TMP_DIR=""

cleanup() { if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- Subfinder ---
find_subfinder() {
  if [ -n "${SUBFINDER_PATH:-}" ] && [ -x "$SUBFINDER_PATH" ]; then echo "$SUBFINDER_PATH"; return 0; fi
  if have subfinder; then command -v subfinder; return 0; fi
  for p in "$INSTALL_DIR/subfinder" "$HOME/go/bin/subfinder"; do
    if [ -x "$p" ]; then echo "$p"; return 0; fi
  done
  return 1
}

download() {  # download <url> <output file>
  if have curl; then curl -fsSL "$1" -o "$2"
  elif have wget; then wget -q "$1" -O "$2"
  else die "Neither curl nor wget is installed. Install one of them and try again."
  fi
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "No sha256sum or shasum found, cannot verify the download."
  fi
}

install_subfinder() {
  local existing
  if existing="$(find_subfinder)"; then
    say "Subfinder already installed: $existing"
    return 0
  fi

  local os arch os_name arch_name
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os" in
    Linux)  os_name="linux" ;;
    Darwin) os_name="macOS" ;;
    *) die "Unsupported system '$os'. On Windows use WSL, or install Subfinder from https://github.com/projectdiscovery/subfinder#installation" ;;
  esac
  case "$arch" in
    x86_64|amd64)  arch_name="amd64" ;;
    aarch64|arm64) arch_name="arm64" ;;
    armv7l|armv6l|arm) arch_name="arm" ;;
    i386|i686)     arch_name="386" ;;
    *) die "Unsupported CPU '$arch'." ;;
  esac

  have python3 || die "python3 is required (it is used to unpack the download)."

  local name="subfinder_${SUBFINDER_VERSION}_${os_name}_${arch_name}.zip"
  local base="${SUBFINDER_BASE_URL:-https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}}"
  TMP_DIR="$(mktemp -d)"
  local tmp="$TMP_DIR"

  say "Downloading Subfinder v${SUBFINDER_VERSION} (${os_name}/${arch_name})..."
  download "$base/$name" "$tmp/$name" || die "Download failed: $base/$name"
  download "$base/subfinder_${SUBFINDER_VERSION}_checksums.txt" "$tmp/checksums.txt" \
    || die "Could not download the checksums file, refusing to install an unverified file."

  say "Verifying checksum..."
  local expected actual
  expected="$(awk -v f="$name" '$2==f {print $1}' "$tmp/checksums.txt")"
  [ -n "$expected" ] || die "No checksum listed for $name."
  actual="$(sha256_of "$tmp/$name")"
  [ "$expected" = "$actual" ] || die "Checksum does NOT match. Download is corrupt or tampered with. Nothing was installed."

  say "Installing to $INSTALL_DIR ..."
  python3 - "$tmp/$name" "$tmp" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extract("subfinder", sys.argv[2])
PY
  mkdir -p "$INSTALL_DIR"
  install -m 755 "$tmp/subfinder" "$INSTALL_DIR/subfinder"
  say "Installed: $("$INSTALL_DIR/subfinder" -version 2>&1 | grep -i version | head -1 | sed 's/\x1b\[[0-9;]*m//g')"

  case ":$ORIGINAL_PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH. This script works anyway. To use 'subfinder' in any terminal, run:"
       echo "    echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc" >&2 ;;
  esac

  say "Tip: more API keys = more subdomains. Run 'subfinder -ls' to see the sources (marked * need a key)"
  echo "    and put keys in ~/.config/subfinder/provider-config.yaml (never commit that file)."
}

# ------------------------------------------------------------------- Python ---
setup_python() {
  have python3 || die "python3 is not installed."
  if [ ! -d "$VENV_DIR" ]; then
    say "Creating Python environment (.venv)..."
    python3 -m venv "$VENV_DIR" 2>/dev/null \
      || die "Could not create a virtual environment. On Debian/Ubuntu run: sudo apt install python3-venv"
  fi
  # shellcheck disable=SC1091
  . "$VENV_DIR/bin/activate"
  local stamp="$VENV_DIR/.deps-installed"
  if [ ! -f "$stamp" ] || [ "$PROJECT_DIR/pyproject.toml" -nt "$stamp" ]; then
    say "Installing ExposureIQ and its Python packages..."
    pip install -q --upgrade pip
    pip install -q -e "$PROJECT_DIR[dev]"
    touch "$stamp"
  fi
}

link_command() {
  # Make 'exposureiq' work in any terminal, without activating the virtual environment.
  mkdir -p "$INSTALL_DIR"
  ln -sf "$VENV_DIR/bin/exposureiq" "$INSTALL_DIR/exposureiq"
  case ":$ORIGINAL_PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH, so typing 'exposureiq' alone will not work yet. Run:"
       echo "    echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" >&2 ;;
  esac
}

ensure_ready() {
  cd "$PROJECT_DIR"
  [ -d "$PROJECT_DIR/exposureiq" ] || die "Folder 'exposureiq/' not found. Keep run.sh in the project root, next to exposureiq/."
  install_subfinder
  setup_python
  link_command
  local sf; sf="$(find_subfinder)" || die "Subfinder not found after install."
  export SUBFINDER_PATH="$sf"
}

# ----------------------------------------------------------------- Commands ---
cmd_install() { ensure_ready; say "Everything is ready. Try:  exposureiq scan example.com"; }

cmd_test() { ensure_ready; say "Running tests..."; python -m pytest -q; }

cmd_scan() {
  [ $# -ge 1 ] || die "usage: ./run.sh scan <domain> [options]   (see: exposureiq scan --help)"
  ensure_ready
  exposureiq scan "$@"
}

# --------------------------------------------------------------------- Main ---
case "${1:-help}" in
  install)         cmd_install ;;
  test)            cmd_test ;;
  scan)            shift; cmd_scan "$@" ;;
  help|-h|--help)  usage ;;
  *)               usage; die "Unknown command: $1" ;;
esac
