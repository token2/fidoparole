#!/usr/bin/env bash
# build.sh — build FidoParole on Linux or macOS.
#
# Builds upstream libfido2 $LIBFIDO2_TAG (USB HID only) and links it
# statically, so the binary never picks up a different system libfido2.
#
# Prerequisites
#   Debian/Ubuntu: sudo apt install build-essential cmake pkg-config git \
#                  libcbor-dev libssl-dev zlib1g-dev libudev-dev \
#                  libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev
#   macOS:         brew install cmake pkg-config libcbor openssl@3
#   Rust:          https://rustup.rs
#
# Usage: ./build.sh [--dev] [--rebuild-fido2]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE"
TAG="${LIBFIDO2_TAG:-1.15.0}"
FIDO="$ROOT/deps/libfido2"
DEV=0; REBUILD=0
for a in "$@"; do
  case "$a" in
    --dev) DEV=1 ;;
    --rebuild-fido2) REBUILD=1 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done

step() { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

# Rebuild when the build configuration changes (the marker records it).
SIG="libfido2 $TAG upstream hid-only v2"
MARK="$FIDO/build/.vault-build"
if [[ $REBUILD == 1 || ! -f "$FIDO/build/src/libfido2.a" || "$(cat "$MARK" 2>/dev/null)" != "$SIG" ]]; then
  step "libfido2 $TAG (upstream, USB HID)"
  if [[ ! -f "$FIDO/CMakeLists.txt" ]]; then
    mkdir -p "$ROOT/deps"
    git clone --depth 1 --branch "$TAG" https://github.com/Yubico/libfido2 "$FIDO"
  fi
  ( cd "$FIDO" && git checkout -- . && git clean -fdq -e build )
  rm -f "$FIDO/build/CMakeCache.txt"
  EXTRA=()
  if [[ "$(uname)" == "Darwin" ]]; then
    OSSL="$(brew --prefix openssl@3)"
    EXTRA+=("-DCMAKE_PREFIX_PATH=$OSSL;$(brew --prefix libcbor)")
    export PKG_CONFIG_PATH="$OSSL/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  fi
  cmake -S "$FIDO" -B "$FIDO/build" -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_MANPAGES=OFF -DBUILD_TOOLS=OFF \
    -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=ON -DUSE_PCSC=OFF "${EXTRA[@]}"
  cmake --build "$FIDO/build" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  printf '%s' "$SIG" > "$MARK"
fi

export FIDO2_LIB_DIR="$FIDO/build/src"
export FIDO2_LIB_NAME=fido2
export FIDO2_LINK_STATIC=1
if [[ "$(uname)" == "Darwin" ]]; then
  export RUSTFLAGS="${RUSTFLAGS:-} -L $(brew --prefix openssl@3)/lib -L $(brew --prefix libcbor)/lib"
fi

cd "$HERE/src-tauri"
if [[ $DEV == 1 ]]; then
  step "Debug build"
  cargo build
  exec "${CARGO_TARGET_DIR:-target}/debug/fidoparole"
fi
step "Release build"
cargo build --release
mkdir -p "$ROOT/dist/fidoparole"
cp "${CARGO_TARGET_DIR:-target}/release/fidoparole" "$ROOT/dist/fidoparole/"
echo
echo "Built: $ROOT/dist/fidoparole/fidoparole"
[[ "$(uname)" == "Linux" ]] && echo "Linux: install the usual FIDO udev rules so your user can open the key's HID device." || true
