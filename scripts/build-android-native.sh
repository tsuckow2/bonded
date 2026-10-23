#!/usr/bin/env bash
# Build the bonded-ffi native library for Android and copy it into jniLibs.
# Run from the workspace root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

JNILIBS_DIR="$WORKSPACE_ROOT/android/android/app/src/main/jniLibs"

# --- Android NDK toolchain, derived from the environment (never hardcoded) ---
# The NDK comes from ANDROID_NDK_HOME, or ANDROID_HOME/ndk/<version>. The
# per-target linker/CC/CXX/AR exports below replace the machine-specific
# paths that used to live in .cargo/config.toml, so this script — and the
# Gradle buildRustAndroidNative task that invokes it — works anywhere.
NDK_VERSION="28.2.13676358"
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  NDK_HOME="$ANDROID_NDK_HOME"
elif [ -n "${ANDROID_HOME:-}" ]; then
  NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
else
  echo "error: set ANDROID_NDK_HOME or ANDROID_HOME so the Android NDK can be located" >&2
  exit 1
fi
if [ ! -d "$NDK_HOME" ]; then
  echo "error: Android NDK not found at $NDK_HOME" >&2
  exit 1
fi
export ANDROID_NDK_HOME="$NDK_HOME"
LLVM_BIN="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$LLVM_BIN/aarch64-linux-android21-clang"
export CC_aarch64_linux_android="$LLVM_BIN/aarch64-linux-android21-clang"
export CXX_aarch64_linux_android="$LLVM_BIN/aarch64-linux-android21-clang++"
export AR_aarch64_linux_android="$LLVM_BIN/llvm-ar"

export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$LLVM_BIN/armv7a-linux-androideabi21-clang"
export CC_armv7_linux_androideabi="$LLVM_BIN/armv7a-linux-androideabi21-clang"
export CXX_armv7_linux_androideabi="$LLVM_BIN/armv7a-linux-androideabi21-clang++"
export AR_armv7_linux_androideabi="$LLVM_BIN/llvm-ar"

export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$LLVM_BIN/x86_64-linux-android21-clang"
export CC_x86_64_linux_android="$LLVM_BIN/x86_64-linux-android21-clang"
export CXX_x86_64_linux_android="$LLVM_BIN/x86_64-linux-android21-clang++"
export AR_x86_64_linux_android="$LLVM_BIN/llvm-ar"

echo "Ensuring Android Rust targets are installed..."
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

echo "Building bonded-ffi for aarch64-linux-android (arm64 physical devices)..."
cargo build --target aarch64-linux-android -p bonded-ffi --release

echo "Building bonded-ffi for armv7-linux-androideabi (32-bit physical devices)..."
cargo build --target armv7-linux-androideabi -p bonded-ffi --release

echo "Building bonded-ffi for x86_64-linux-android (emulators)..."
cargo build --target x86_64-linux-android -p bonded-ffi --release

echo "Copying .so files to jniLibs..."
mkdir -p "$JNILIBS_DIR/arm64-v8a"
mkdir -p "$JNILIBS_DIR/armeabi-v7a"
mkdir -p "$JNILIBS_DIR/x86_64"

cp "$WORKSPACE_ROOT/target/aarch64-linux-android/release/libbonded_ffi.so" \
   "$JNILIBS_DIR/arm64-v8a/libbonded_ffi.so"

cp "$WORKSPACE_ROOT/target/armv7-linux-androideabi/release/libbonded_ffi.so" \
   "$JNILIBS_DIR/armeabi-v7a/libbonded_ffi.so"

cp "$WORKSPACE_ROOT/target/x86_64-linux-android/release/libbonded_ffi.so" \
   "$JNILIBS_DIR/x86_64/libbonded_ffi.so"

echo "Done. Native libraries are ready at:"
echo "  $JNILIBS_DIR/arm64-v8a/libbonded_ffi.so ($(du -sh "$JNILIBS_DIR/arm64-v8a/libbonded_ffi.so" | cut -f1))"
echo "  $JNILIBS_DIR/armeabi-v7a/libbonded_ffi.so ($(du -sh "$JNILIBS_DIR/armeabi-v7a/libbonded_ffi.so" | cut -f1))"
echo "  $JNILIBS_DIR/x86_64/libbonded_ffi.so ($(du -sh "$JNILIBS_DIR/x86_64/libbonded_ffi.so" | cut -f1))"
