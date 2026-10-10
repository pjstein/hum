#!/usr/bin/env bash
# Pinned, isolated MLS reference integration; does not change Hum Cargo/reference deps.
set -euo pipefail
probe_dir=$(cd "$(dirname "$0")" && pwd)
source_dir="${HUM_MLS_SOURCE:-${TMPDIR:-/tmp}/hum-mls-rs-056}"
commit=8f1b43f447a792ff9307f1c2c7f54da63914870e
if [[ ! -d "$source_dir/.git" ]]; then
  git clone --branch 0.56.0 --depth 1 https://github.com/awslabs/mls-rs.git "$source_dir"
fi
[[ "$(git -C "$source_dir" rev-parse HEAD)" = "$commit" ]] || {
  echo "MLS source revision differs from pinned commit" >&2; exit 1;
}
patch_file="$probe_dir/uniffi-hum-profile.patch"
if git -C "$source_dir" apply --reverse --check "$patch_file" 2>/dev/null; then
  : # This exact patch is already present.
else
  git -C "$source_dir" apply --check "$patch_file"
  git -C "$source_dir" apply "$patch_file"
fi
cp "$probe_dir/upstream.Cargo.lock" "$source_dir/Cargo.lock"
if [[ "$(uname -s)" = Darwin ]]; then
  export OPENSSL_DIR="${OPENSSL_DIR:-/opt/homebrew/opt/openssl@3}"
  library=libmls_rs_uniffi.dylib
else
  library=libmls_rs_uniffi.so
fi
mkdir -p "$probe_dir/out/python"
cd "$source_dir"
cargo test --locked -p mls-rs-uniffi --lib --test scenarios
cargo build --locked -p mls-rs-uniffi
cargo run --locked -p uniffi-bindgen -- generate --library "target/debug/$library" \
  --language python --out-dir "$probe_dir/out/python" --no-format
cp "target/debug/$library" "$probe_dir/out/python/"
PYTHONPATH="$probe_dir/out/python" python3 "$probe_dir/profile_checks.py" | tee "$probe_dir/out/profile-results.json"
