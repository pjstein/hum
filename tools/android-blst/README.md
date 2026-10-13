# Android blst / UniFFI feasibility probe

This isolated, locked Cargo workspace checks approved `blst` 0.3.17 through a
UniFFI 0.32.2 exported function. It is not the Hum BBS implementation or a shipped
app dependency. The synthetic BLS signature exercise forces key generation,
subgroup validation, hash-to-curve, scalar multiplication and pairing code into
the artifact. No primitive is implemented here.

On macOS:

```sh
tools/android-blst/install-ndk-macos.sh
rustup target add aarch64-linux-android
ANDROID_NDK_HOME="$HOME/Library/Caches/hum-android-blst/android-ndk-r29" tools/android-blst/run.sh
```

On Linux, install the official NDK r29 and pass its directory in
`ANDROID_NDK_HOME`. `run.sh` uses Android API 26 and the Rust toolchain pinned by
the repository. It runs the host tests, calls generated Python bindings against
the host library, builds an arm64 Android shared library and executable, generates
Kotlin bindings directly from the Android ELF metadata, and checks the ELF machine
and exported UniFFI symbol. `out/android/` contains artifacts, hashes and inspection
reports; generated files and binaries are ignored by Git. The lockfile is tracked.

The host binding test exercises the actual UniFFI call and record serialization.
The cross-build command alone does not imply Kotlin/JNA or Android runtime
execution. The separate runtime harness below compiles and exercises that boundary.

With a connected development Android device or emulator selected by `adb`, run
`tools/android-blst/run-device.sh` to execute the cross-built native probe. That
optional command executes the Rust/blst code on Android but still does not test a
Kotlin-to-UniFFI call. The separate `run-kotlin.sh` command tests Kotlin-to-UniFFI calls.

See [feasibility findings](../../docs/research/android-blst-feasibility.md) for the
actual run and its limits.

## Kotlin runtime probe

The isolated `runtime/` Gradle project packages generated Kotlin from `out/android/`
and the same arm64 `.so`, with JNA 5.18.1. It is a synthetic test APK with no
network permission, user data or production app dependency. Its instrumentation
calls `runProbe()` twenty times and asserts all six returned fields (120 checks).
`run-kotlin.sh` requires explicit instrumentation success, not merely adb exit 0.

On Apple Silicon macOS, after the existing cross-build:

```sh
tools/android-blst/install-runtime-macos.sh
python3 tools/android-blst/run-emulator.py
```

The installer verifies pinned JDK 21, Android command-line tools and Gradle 8.13
archives, then installs Google's SDK packages (with license prompts). Everything
lives under `~/Library/Caches/hum-android-runtime`; override with
`HUM_ANDROID_RUNTIME_CACHE`. Python 3.12+ is required. SDK package revisions are
recorded in evidence; Google's unversioned emulator/package download endpoints
can supply newer revisions on a later run. Gradle uses AGP 8.13.2, Kotlin 2.2.21
and the checked-in dependency lockfile.

`run-emulator.py` creates its own API-35 arm64 AVD, refuses occupied ports 5580/5581,
boots without a window, bounds boot/test time, and stops only the process it
created. To run on another explicitly selected development target instead:

```sh
ANDROID_HOME=/path/to/sdk JAVA_HOME=/path/to/jdk \
  GRADLE=/path/to/gradle-8.13/bin/gradle ANDROID_SERIAL=emulator-5554 \
  tools/android-blst/run-kotlin.sh
```

Results and APK/build/emulator output are under ignored `out/runtime/` and
`runtime/app/build/`. This demonstrates the BLS probe's Kotlin/JNA/UniFFI loader
and execution path only; Hum BBS integration, real device performance and outside
cryptography review remain separate work.
