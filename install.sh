#!/bin/sh

set -eu

WHA_DEFAULT_REPOSITORY="https://github.com/kappa9999/white-hat-agent"
WHA_DEFAULT_REF="main"
WHA_DEFAULT_PYTHON="3.12"
WHA_DEFAULT_UV_INSTALLER="https://astral.sh/uv/install.sh"

wha_info() {
  printf '%s\n' "white-hat-agent: $*"
}

wha_warn() {
  printf '%s\n' "white-hat-agent: warning: $*" >&2
}

wha_fail() {
  printf '%s\n' "white-hat-agent: error: $*" >&2
  exit 1
}

wha_resolve_command() {
  if [ -n "${WHA_UV_BIN:-}" ]; then
    if [ -x "$WHA_UV_BIN" ]; then
      printf '%s\n' "$WHA_UV_BIN"
      return 0
    fi
    if command -v "$WHA_UV_BIN" >/dev/null 2>&1; then
      command -v "$WHA_UV_BIN"
      return 0
    fi
    wha_fail "WHA_UV_BIN does not resolve to an executable: $WHA_UV_BIN"
  fi

  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi

  if [ -n "${UV_INSTALL_DIR:-}" ] && [ -x "$UV_INSTALL_DIR/uv" ]; then
    printf '%s\n' "$UV_INSTALL_DIR/uv"
    return 0
  fi
  if [ -n "${XDG_BIN_HOME:-}" ] && [ -x "$XDG_BIN_HOME/uv" ]; then
    printf '%s\n' "$XDG_BIN_HOME/uv"
    return 0
  fi
  if [ -n "${HOME:-}" ] && [ -x "${HOME}/.local/bin/uv" ]; then
    printf '%s\n' "${HOME}/.local/bin/uv"
    return 0
  fi
  if [ -n "${HOME:-}" ] && [ -x "${HOME}/.cargo/bin/uv" ]; then
    printf '%s\n' "${HOME}/.cargo/bin/uv"
    return 0
  fi
  return 1
}

wha_download() {
  wha_download_url=$1
  wha_download_path=$2
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -LsSf "$wha_download_url" -o "$wha_download_path"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q "$wha_download_url" -O "$wha_download_path"
    return
  fi
  wha_fail "curl or wget is required to bootstrap uv"
}

wha_install_uv() {
  wha_uv_installer_url=${WHA_UV_INSTALLER_URL:-$WHA_DEFAULT_UV_INSTALLER}
  wha_tmp_base=${TMPDIR:-/tmp}
  wha_uv_script="$wha_tmp_base/white-hat-agent-uv-install.$$"
  trap 'rm -f "$wha_uv_script"' EXIT HUP INT TERM

  wha_info "uv was not found; downloading the official uv installer"
  wha_download "$wha_uv_installer_url" "$wha_uv_script"
  sh "$wha_uv_script"
  rm -f "$wha_uv_script"
  trap - EXIT HUP INT TERM
}

wha_repository=${WHA_REPOSITORY:-$WHA_DEFAULT_REPOSITORY}
wha_repository=${wha_repository%/}
wha_ref=${WHA_REF:-$WHA_DEFAULT_REF}
wha_python=${WHA_PYTHON:-$WHA_DEFAULT_PYTHON}
wha_source_url=${WHA_SOURCE_URL:-"$wha_repository/archive/refs/heads/$wha_ref.zip"}
wha_package=${WHA_PACKAGE:-"white-hat-agent @ $wha_source_url"}

wha_uv=$(wha_resolve_command || true)
if [ -z "$wha_uv" ]; then
  wha_install_uv
  wha_uv=$(wha_resolve_command || true)
fi
[ -n "$wha_uv" ] || wha_fail "uv installation completed but the executable could not be located"

wha_info "installing or refreshing White Hat Agent Core with Python $wha_python"
"$wha_uv" tool install --reinstall --refresh --python "$wha_python" "$wha_package"

if [ "${WHA_SKIP_PATH_UPDATE:-0}" != "1" ]; then
  if ! "$wha_uv" tool update-shell; then
    wha_warn "could not update the shell profile automatically"
  fi
fi

wha_bin_dir=$("$wha_uv" tool dir --bin)
wha_executable="$wha_bin_dir/wha"
[ -x "$wha_executable" ] || wha_fail "installation finished but wha was not found in $wha_bin_dir"
wha_version=$("$wha_executable" --version)

printf '\n%s\n' "$wha_version is ready."
printf '%s\n' "Executable: $wha_executable"
printf '%s\n' "Start a new shell if 'wha' is not yet on PATH."
printf '\n%s\n' "Next steps:"
printf '%s\n' "  wha init white-hat-workspace"
printf '%s\n' "  cd white-hat-workspace"
printf '%s\n' "  wha doctor"
