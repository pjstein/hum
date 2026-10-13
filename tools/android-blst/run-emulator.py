#!/usr/bin/env python3
"""Boot a dedicated disposable arm64 emulator and run the Kotlin probe."""

import os
import socket
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parent
cache = Path(
    os.environ.get(
        "HUM_ANDROID_RUNTIME_CACHE", Path.home() / "Library/Caches/hum-android-runtime"
    )
)
env = os.environ.copy()
env.update(
    {
        "JAVA_HOME": str(cache / "jdk/jdk-21.0.12.1+1/Contents/Home"),
        "ANDROID_HOME": str(cache / "sdk"),
        "ANDROID_AVD_HOME": str(cache / "avd"),
        "GRADLE_USER_HOME": str(cache / "gradle-home"),
        "GRADLE": str(cache / "gradle-8.13/bin/gradle"),
        "ANDROID_SERIAL": "emulator-5580",
    }
)
Path(env["ANDROID_AVD_HOME"]).mkdir(parents=True, exist_ok=True)
out = root / "out/runtime"
out.mkdir(parents=True, exist_ok=True)
sdk = Path(env["ANDROID_HOME"])
# Do not target or stop an existing emulator owned by another task.
for port in (5580, 5581):
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(
                f"Port {port} occupied; refusing to reuse another emulator"
            )
subprocess.run(
    [
        str(sdk / "cmdline-tools/cmdline-tools/bin/avdmanager"),
        "create",
        "avd",
        "--force",
        "--name",
        "hum-blst-api35",
        "--package",
        "system-images;android-35;google_apis;arm64-v8a",
    ],
    input="no\n",
    text=True,
    env=env,
    check=True,
    timeout=120,
)
adb = [str(sdk / "platform-tools/adb"), "-s", env["ANDROID_SERIAL"]]
with (out / "emulator.txt").open("w") as log:
    emulator = subprocess.Popen(
        [
            str(sdk / "emulator/emulator"),
            "-avd",
            "hum-blst-api35",
            "-port",
            "5580",
            "-no-window",
            "-no-audio",
            "-no-snapshot",
            "-wipe-data",
            "-no-boot-anim",
            "-gpu",
            "swiftshader_indirect",
            "-memory",
            "2048",
        ],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if emulator.poll() is not None:
                raise RuntimeError(
                    f"Emulator exited {emulator.returncode}; see {out / 'emulator.txt'}"
                )
            status = subprocess.run(
                adb + ["shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
                check=False,
            )
            if status.returncode == 0 and status.stdout.strip() == "1":
                break
            time.sleep(2)
        else:
            raise TimeoutError("Emulator did not boot within 240 seconds")
        subprocess.run([str(root / "run-kotlin.sh")], env=env, check=True, timeout=600)
    finally:
        emulator.terminate()
        try:
            emulator.wait(timeout=15)
        except subprocess.TimeoutExpired:
            emulator.kill()
            emulator.wait(timeout=5)
