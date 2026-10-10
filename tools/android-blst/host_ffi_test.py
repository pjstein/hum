"""Call the compiled Rust implementation through generated UniFFI Python bindings."""
from hum_android_blst_probe import run_probe

result = run_probe()
assert result.valid_signature
assert result.altered_message_rejected
assert result.malformed_public_key_rejected
assert result.malformed_signature_rejected
assert (result.public_key_bytes, result.signature_bytes) == (48, 96)
print("UniFFI host boundary passed: valid signature; altered message and malformed points rejected; 48/96 bytes")
