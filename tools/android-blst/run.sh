#!/usr/bin/env bash
# Reproducible isolated probe; install the NDK separately and point ANDROID_NDK_HOME to it.
set -euo pipefail
cd "$(dirname "$0")"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK r29 directory}"
case "$(uname -s)" in
  Darwin) ndk_host=darwin-x86_64; host_lib=libhum_android_blst_probe.dylib ;;
  Linux) ndk_host=linux-x86_64; host_lib=libhum_android_blst_probe.so ;;
  *) echo "This probe script supports macOS/Linux hosts" >&2; exit 1 ;;
esac
ndk_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$ndk_bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
mkdir -p out/host out/android
cargo test --locked
cargo build --locked --lib
cargo run --locked --features bindgen --bin uniffi-bindgen -- generate \
  --library "target/debug/$host_lib" --language python --out-dir out/host --no-format
cp "target/debug/$host_lib" out/host/
PYTHONPATH="$PWD/out/host" python3 host_ffi_test.py
cargo build --locked --release --target aarch64-linux-android --lib --bin android-probe
android_lib=target/aarch64-linux-android/release/libhum_android_blst_probe.so
cargo run --locked --features bindgen --bin uniffi-bindgen -- generate \
  --library "$android_lib" --language kotlin --out-dir out/android --no-format
"$ndk_bin/llvm-readelf" -h -l -d "$android_lib" > out/android/elf-report.txt
"$ndk_bin/llvm-nm" -D --defined-only "$android_lib" > out/android/exported-symbols.txt
grep -q 'AArch64' out/android/elf-report.txt
grep -q 'uniffi_hum_android_blst_probe_fn_func_run_probe' out/android/exported-symbols.txt
cp "$android_lib" target/aarch64-linux-android/release/android-probe out/android/
python3 - <<'PY'
import hashlib, json
from pathlib import Path
names = ['libhum_android_blst_probe.so', 'android-probe']
result = {n: {'sha256': hashlib.sha256((Path('out/android')/n).read_bytes()).hexdigest(),
              'bytes': (Path('out/android')/n).stat().st_size} for n in names}
Path('out/android/artifacts.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
PY
printf '%s\n' 'Android cross-build and Kotlin binding generation passed. No Android runtime execution is implied.'
