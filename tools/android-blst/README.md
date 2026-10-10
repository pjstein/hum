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
It does not imply Kotlin/JNA or Android runtime execution. Kotlin binding source
is generated but not compiled into an APK in this probe.

With a connected development Android device or emulator selected by `adb`, run
`tools/android-blst/run-device.sh` to execute the cross-built native probe. That
optional command executes the Rust/blst code on Android but still does not test a
Kotlin-to-UniFFI call. The outstanding app integration check needs an Android test
APK using the generated Kotlin, JNA and arm64 `.so`.

See [feasibility findings](../../docs/research/android-blst-feasibility.md) for the
actual run and its limits.
