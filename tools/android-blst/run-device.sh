#!/usr/bin/env bash
# Explicitly opt in to a connected development Android target selected by adb.
set -euo pipefail
cd "$(dirname "$0")"
adb get-state
adb push out/android/android-probe /data/local/tmp/hum-blst-probe
adb shell chmod 700 /data/local/tmp/hum-blst-probe
adb shell /data/local/tmp/hum-blst-probe
