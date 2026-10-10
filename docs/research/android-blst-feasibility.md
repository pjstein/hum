# Android blst and UniFFI feasibility

2026-10-09 · ADR 0110 follow-up · `seam:` pairing-library integration and FFI

**The approved blst 0.3.17 builds into an arm64 Android shared library with a
UniFFI export.** Kotlin bindings were generated from that Android library. A host
Python binding called the same exported Rust operation through UniFFI and passed
the cryptographic checks. No Android device/emulator or Kotlin runtime call was
executed, so this proves the cross-build and binding-generation portion of the
ADR, not a finished phone integration or BBS implementation.

## Probe and environment

The isolated Cargo workspace is [`tools/android-blst`](../../tools/android-blst/README.md).
It does not change the root Cargo dependency graph, `hum-ffi`, or the Python
reference. Its direct dependencies are exactly `blst = 0.3.17` (approved by
ADR 0110) and `uniffi = 0.32.2` (pinned feasibility tooling), with a committed
lockfile. The UniFFI CLI feature is enabled only for the host binding generator.

The exported `run_probe` uses blst's safe BLS `min_pk` API with synthetic fixed
IKM. It validates serialized public keys and signatures with subgroup checks,
verifies a signature, rejects the signature over an altered message, and rejects
malformed compressed public keys and signatures. The exported record carries
these four booleans and the expected 48-byte/96-byte encoding lengths. The
Rust test and generated Python caller assert all six results. All arithmetic,
hashing and signature operations come from blst; this is not an implementation
of Hum's BBS constructions or its eventual unsafe wrapper.

Actual environment:

| Component | Value |
| --- | --- |
| Host | Apple Silicon macOS, `aarch64-apple-darwin` |
| Rust | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| Target | `aarch64-linux-android` |
| Android API | 26 |
| NDK | r29, `29.0.14206865` |
| NDK compiler | Android clang 21.0.0, build 13989888 |
| Pairing library | blst 0.3.17, default features |
| UniFFI | 0.32.2 |

No SDK, NDK, `adb`, or emulator was present initially. The Rust target was added
with `rustup target add`. The official NDK archive was installed into
`~/Library/Caches/hum-android-blst/android-ndk-r29`; no Android Studio or global
SDK configuration was changed. The installer checks Google's published archive
SHA-1 `03d29fbb57e3c05a7d53597dd011d856c1456a4f` and 1,049,519,838 bytes were
downloaded. Sources: [NDK downloads](https://developer.android.com/ndk/downloads),
[Google repository metadata](https://dl.google.com/android/repository/repository2-3.xml),
and [UniFFI binding generation](https://mozilla.github.io/uniffi-rs/latest/bindings.html).

## Actual results

`ANDROID_NDK_HOME="$HOME/Library/Caches/hum-android-blst/android-ndk-r29" tools/android-blst/run.sh`
exited 0. Its relevant output was:

```text
test result: ok. 1 passed; 0 failed
UniFFI host boundary passed: valid signature; altered message and malformed points rejected; 48/96 bytes
Android cross-build and Kotlin binding generation passed. No Android runtime execution is implied.
```

`cargo clippy --manifest-path tools/android-blst/Cargo.toml --locked --all-targets -- -D warnings`
also exited 0. The Python check calls generated bindings and loads the compiled
host dylib; it is not a direct call to the Rust test.

The Android `.so` is an ELF64 little-endian `DYN` shared object, machine AArch64.
All three `LOAD` segments have `0x4000` (16 KiB) alignment. Its only dynamic
`NEEDED` entries are `libdl.so` and `libc.so`. It exports both
`uniffi_hum_android_blst_probe_fn_func_run_probe` and the matching checksum symbol.
The generated Kotlin has `ProbeResult` and `runProbe()`; metadata was read from
the Android `.so`, not substituted from the host library.

| Artifact under `tools/android-blst/out/android/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `libhum_android_blst_probe.so` | 902080 | `4f9cf441705129756f333adad9b51de05849f1033a3f2cae152f3e3557d08017` |
| `android-probe` native executable | 836648 | `42b3e2d78baad1d79dc9ca46dbb1ae5b960d33008619424638f30596133739b9` |

The artifacts and generated Kotlin are local build outputs, excluded from Git.
Their [hash manifest](../../tools/android-blst/evidence/artifacts.json),
[ELF inspection](../../tools/android-blst/evidence/elf-report.txt), and
[exported symbols](../../tools/android-blst/evidence/exported-symbols.txt) are
committed evidence. Hashes identify this run; the scripts and lockfile make the
probe repeatable, but bit-for-bit reproducibility across hosts and paths has not
been established.

## Remaining phone proof

1. Compile the generated Kotlin with JNA into an Android instrumented test APK,
   package the arm64 `.so`, and call `runProbe()` on a device/emulator. This
   closes Android loader, Kotlin/JNA, generated ABI and runtime execution together.
2. `run-device.sh` can separately push and execute the native test executable on
   an explicitly selected development `adb` target. It has not been run here and
   does not replace the Kotlin test.
3. Integrate the actual Hum BBS wrapper into `hum-ffi`, run the published draft
   vectors and independent Python comparisons through that boundary, and measure
   performance on supported devices. This probe exercises BLS library operations,
   not BBS, blind issuance, pseudonyms, zeroization policy or constant-time review.
4. Include the new unsafe wrapper and blst's unaudited newer code in the outside
   cryptography review required by ADR 0110. A successful build is not that review.

Recommendation: mark the **arm64 cross-build feasibility** proven and retain the
**Android Kotlin runtime integration** follow-up. No app or production library
choice beyond the already approved blst version is made by this harness.
