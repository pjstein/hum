# apps

The native clients. There is no web client and no over-the-air code update
path (invariant 8 in `CLAUDE.md`). All protocol, crypto, storage and state
logic lives in `core/` and reaches the apps through `hum-ffi`.

| Directory | Owner |
| --- | --- |
| `ios/` | W1-09 iOS (SwiftUI) |
| `android/` | W1-10 Android (Jetpack Compose) |
