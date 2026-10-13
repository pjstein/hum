#!/usr/bin/env bash
# Isolated Apple Silicon tools; sdkmanager asks for Google's SDK licenses.
set -euo pipefail
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'Requires Apple Silicon macOS' >&2; exit 1; }
cache="${HUM_ANDROID_RUNTIME_CACHE:-$HOME/Library/Caches/hum-android-runtime}"
mkdir -p "$cache"
export HUM_ANDROID_RUNTIME_CACHE="$cache"
python3 - <<'PY'
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile

root = Path(os.environ['HUM_ANDROID_RUNTIME_CACHE'])
packages = [
    ('jdk.tar.gz', 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz', '3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998', 'jdk'),
    ('cmdline.zip', 'https://dl.google.com/android/repository/commandlinetools-mac_arm64-15859902_latest.zip', '835b62a26162b229b441d1f6d4680383815a270809eb33522c0d480fa5002c4e', 'sdk/cmdline-tools'),
    ('gradle.zip', 'https://services.gradle.org/distributions/gradle-8.13-bin.zip', '20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78', '.'),
]
for name, url, checksum, target in packages:
    path = root / name
    if not path.exists():
        subprocess.run(['curl', '-fL', '--retry', '2', url, '-o', str(path)], check=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise SystemExit(f'Checksum mismatch: {path}; remove invalid download before retrying')
    if name.endswith('.tar.gz'):
        with tarfile.open(path) as archive:
            archive.extractall(root / target, filter='data')
    else:
        with zipfile.ZipFile(path) as archive:
            archive.extractall(root / target)
PY
chmod +x "$cache"/sdk/cmdline-tools/cmdline-tools/bin/* "$cache/gradle-8.13/bin/gradle"
export JAVA_HOME="$cache/jdk/jdk-21.0.12.1+1/Contents/Home"
"$cache/sdk/cmdline-tools/cmdline-tools/bin/sdkmanager" --sdk_root="$cache/sdk" \
  'platform-tools' 'platforms;android-35' 'build-tools;35.0.0' 'emulator' \
  'system-images;android-35;google_apis;arm64-v8a'
echo "Installed runtime tools under $cache"
