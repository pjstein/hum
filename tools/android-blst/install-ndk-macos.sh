#!/usr/bin/env bash
# Pinned official archive, installed into a private cache without touching Android Studio.
set -euo pipefail
cache_dir="${HUM_ANDROID_CACHE:-$HOME/Library/Caches/hum-android-blst}"
archive="$cache_dir/android-ndk-r29-darwin.zip"
mkdir -p "$cache_dir"
if [[ ! -f "$archive" ]]; then
  curl -fL --retry 2 https://dl.google.com/android/repository/android-ndk-r29-darwin.zip -o "$archive"
fi
# Official repository2-3.xml SHA-1 is an integrity check, not a new crypto primitive.
actual=$(shasum -a 1 "$archive" | cut -d ' ' -f 1)
[[ "$actual" = 03d29fbb57e3c05a7d53597dd011d856c1456a4f ]] || {
  echo 'NDK archive checksum mismatch; remove the incomplete archive and retry' >&2; exit 1;
}
if [[ ! -d "$cache_dir/android-ndk-r29" ]]; then
  unzip -q "$archive" -d "$cache_dir"
fi
printf '%s\n' "ANDROID_NDK_HOME=$cache_dir/android-ndk-r29"
