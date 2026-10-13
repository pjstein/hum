# Android blst and UniFFI feasibility

2026-10-13 · ADR 0110 follow-up · `seam:` pairing-library integration and FFI

**The approved blst 0.3.17 executes through generated Kotlin/JNA/UniFFI on an
arm64 Android emulator.** The October 13 runtime probe compiled an APK using the
Kotlin generated from the Android library, then passed 120 assertions over 20
native calls on Android 15/API 35. Earlier host and cross-build checks also pass.
This proves this synthetic BLS operation's loader and binding execution path;
it does not implement Hum BBS or establish production phone integration.

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

## Kotlin runtime execution on October 13

`python3 tools/android-blst/run-emulator.py` exited 0 after creating and booting
its own disposable arm64 API-35 emulator and building/installing the test APK.
The instrumented caller invoked `runProbe()` twenty times, asserting all four
booleans and both encoding lengths each time. The runner explicitly checks the
instrumentation result because an adb shell exit code alone can conceal test
failure. Output:

```text
INSTRUMENTATION_RESULT: hum_result=PASS: 20 Kotlin-UniFFI-blst calls, 120 assertions
INSTRUMENTATION_CODE: -1
```

The emulator ran Android 15, API 35, arm64-v8a, **4096-byte pages**. This is not
16 KiB runtime validation. The APK's SHA-256 is
`7b1eccb77f793650daf1977a0f653f88c283bc98816d67ab1ec0034da4978516`;
the native library hash matches the earlier cross-build above. The emulator was
terminated after the run. No personal device or application data was accessed.

The isolated test harness uses JDK 21.0.12.1, Gradle 8.13, AGP 8.13.2, Kotlin
2.2.21 and JNA 5.18.1, with locked Gradle dependencies. JDK/Gradle/command-line
archives have pinned SHA-256 checks. The SDK package revisions actually tested
are recorded in [runtime packages](../../tools/android-blst/evidence/runtime-packages.json),
and [runtime result](../../tools/android-blst/evidence/kotlin-runtime.json) and
[instrumentation output](../../tools/android-blst/evidence/kotlin-instrumentation.txt)
provide durable evidence. SDK's emulator and image endpoints can change revisions
on subsequent installs; this does not claim bit-for-bit reproducible APKs.
Sources: [Android command-line tools](https://developer.android.com/studio#command-tools),
[Android emulator CLI](https://developer.android.com/studio/run/emulator-commandline),
[JNA 5.18.1](https://github.com/java-native-access/jna/tree/5.18.1).

## Remaining phone proof

1. Integrate the actual Hum BBS wrapper into `hum-ffi`, run the published draft
   vectors and independent Python comparisons through that boundary, and measure
   performance on supported devices. This probe exercises BLS library operations,
   not BBS, blind issuance, pseudonyms, zeroization policy or constant-time review.
2. Exercise supported physical phones and 16 KiB runtime configurations. ELF
   alignment checks alone are not evidence of execution on 16 KiB pages.
3. Include the new unsafe wrapper and blst's unaudited newer code in the outside
   cryptography review required by ADR 0110. Execution success is not that review.

Both **arm64 cross-build feasibility** and **Android Kotlin runtime feasibility**
are now demonstrated for this probe. No production app or library choice beyond
the already approved blst version is made by this harness.
