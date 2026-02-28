#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/dawnlabsai/lws.git"
INSTALL_DIR="${LWS_INSTALL_DIR:-$HOME/.lws/bin}"
MIN_RUST="1.70.0"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

TMPDIR=""
cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# --- Check prerequisites ---
check_git() {
  command -v git &>/dev/null || err "git is required but not found. Install git first."
}

# --- Check / install Rust ---
install_rust() {
  if command -v rustup &>/dev/null; then
    info "Rust already installed ($(rustc --version))"
  elif command -v rustc &>/dev/null; then
    info "rustc found but no rustup — skipping Rust install"
  else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
}

# --- Ensure cargo is on PATH ---
ensure_cargo() {
  if ! command -v cargo &>/dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
      . "$HOME/.cargo/env"
    else
      err "cargo not found. Install Rust: https://rustup.rs"
    fi
  fi
}

# --- Build ---
build() {
  local src_dir="$1"
  info "Building lws..."
  cd "$src_dir/lws"
  cargo build --workspace --release
  info "Build complete"
}

# --- Install binary to INSTALL_DIR ---
install_bin() {
  local src_dir="$1"
  local bin_path="$src_dir/lws/target/release/lws"

  if [ ! -f "$bin_path" ]; then
    err "Binary not found at $bin_path — build may have failed"
  fi

  mkdir -p "$INSTALL_DIR"
  cp "$bin_path" "$INSTALL_DIR/lws"
  chmod +x "$INSTALL_DIR/lws"
  info "Installed lws to $INSTALL_DIR/lws"
}

# --- Add INSTALL_DIR to PATH in shell rc file ---
setup_path() {
  # Skip if already on PATH
  if echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    return
  fi

  local line="export PATH=\"$INSTALL_DIR:\$PATH\""
  local shell_name
  shell_name="$(basename "${SHELL:-/bin/bash}")"

  case "$shell_name" in
    zsh)
      local rc="$HOME/.zshrc"
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then
        return
      fi
      echo "$line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    bash)
      local rc="$HOME/.bashrc"
      if [ -f "$HOME/.bash_profile" ]; then
        rc="$HOME/.bash_profile"
      fi
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then
        return
      fi
      echo "$line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    fish)
      local rc="$HOME/.config/fish/config.fish"
      local fish_line="fish_add_path $INSTALL_DIR"
      if [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then
        return
      fi
      mkdir -p "$(dirname "$rc")"
      echo "$fish_line" >> "$rc"
      info "Added $INSTALL_DIR to PATH in $rc"
      ;;
    *)
      info "Could not detect shell — add $INSTALL_DIR to your PATH manually"
      ;;
  esac
}

# --- Main ---
main() {
  info "LWS installer"
  echo

  check_git
  install_rust
  ensure_cargo

  TMPDIR="$(mktemp -d)"
  info "Cloning repository..."
  git clone --depth 1 "$REPO" "$TMPDIR" --quiet

  build "$TMPDIR"
  install_bin "$TMPDIR"
  setup_path

  echo
  info "LWS installed successfully!"
  info "Run 'lws --help' to get started (you may need to restart your shell)"
}

main "$@"
