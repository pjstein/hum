# Published reference fixtures

`rfc9578.json` contains the hexadecimal fields from RFC 9578 Appendices A and B,
https://www.rfc-editor.org/rfc/rfc9578.txt (SHA-256 recorded in the JSON). There are
five type-1 and five type-2 fixtures, in source order. Whitespace wrapping is removed;
field names and bytes are preserved. Numeric fixture data are public test inputs,
including all private keys. These are independent known answers, never real secrets.

The reference consumes this data and generates conformance files under `vectors/`.
The isolated Rust probe at `tools/privacy-pass-kat` consumes the same independent
RFC data to test the approved Privacy Pass library.

`runtime/` contains locally authored no-import WebAssembly component probes.
Their scope and ABI limitations are documented in `component_runtime.py` and the
library-lanes handoff.
