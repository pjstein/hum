#!/usr/bin/env bash
# Run against an explicitly selected development emulator/device only.
set -euo pipefail
cd "$(dirname "$0")"
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK 17+ directory}"
: "${GRADLE:?Set GRADLE to the Gradle 8.13 executable}"
: "${ANDROID_SERIAL:?Select the development emulator/device explicitly}"
mkdir -p out/runtime-jni/arm64-v8a out/runtime
# run.sh creates both artifacts from the same pinned UniFFI build.
test -s out/android/libhum_android_blst_probe.so
test -s out/android/uniffi/hum_android_blst_probe/hum_android_blst_probe.kt
cp out/android/libhum_android_blst_probe.so out/runtime-jni/arm64-v8a/
"$GRADLE" -p runtime :app:assembleDebug --console=plain | tee out/runtime/build.txt
export HUM_ANDROID_PROBE_ROOT="$PWD"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(os.environ['HUM_ANDROID_PROBE_ROOT'])
adb = [str(Path(os.environ['ANDROID_HOME']) / 'platform-tools/adb'), '-s', os.environ['ANDROID_SERIAL']]

def call(*args, timeout=120):
    completed = subprocess.run(adb + list(args), capture_output=True, text=True, timeout=timeout, check=True)
    return completed.stdout.strip()

assert call('get-state') == 'device'
abi = call('shell', 'getprop', 'ro.product.cpu.abi')
assert abi == 'arm64-v8a', abi
apk = root / 'runtime/app/build/outputs/apk/debug/app-debug.apk'
call('install', '-r', str(apk))
output = call('shell', 'am', 'instrument', '-w', 'hum.blst.runtime/.ProbeInstrumentation', timeout=60)
(root / 'out/runtime/instrumentation.txt').write_text(output + '\n')
# adb/am may exit zero even when instrumentation fails: inspect both values.
assert 'INSTRUMENTATION_RESULT: hum_result=PASS: 20 Kotlin-UniFFI-blst calls, 120 assertions' in output, output
assert 'INSTRUMENTATION_CODE: -1' in output, output
assert 'FAIL:' not in output, output
report = {
    'status': 'passed', 'scope': 'synthetic BLS feasibility; not Hum BBS or production app',
    'abi': abi, 'android_release': call('shell', 'getprop', 'ro.build.version.release'),
    'api': call('shell', 'getprop', 'ro.build.version.sdk'),
    'emulator': call('shell', 'getprop', 'ro.kernel.qemu') == '1',
    'page_size': call('shell', 'getconf', 'PAGE_SIZE'),
    'kotlin_calls': 20, 'assertions': 120,
    'apk_sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
    'native_sha256': hashlib.sha256((root / 'out/android/libhum_android_blst_probe.so').read_bytes()).hexdigest(),
    'generated_kotlin_sha256': hashlib.sha256((root / 'out/android/uniffi/hum_android_blst_probe/hum_android_blst_probe.kt').read_bytes()).hexdigest(),
}
(root / 'out/runtime/result.json').write_text(json.dumps(report, indent=2) + '\n')
print(output)
print(json.dumps(report, indent=2))
PY
