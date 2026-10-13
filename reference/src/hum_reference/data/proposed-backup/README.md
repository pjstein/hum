# Proposed B1 wordlist

`english.txt` is the exact 2,048-word BIP-39 English wordlist from bitcoin/bips
commit `927b6de9915c9262615a6399de51b200f81e5aa4`, pinned in ADR 0113:
https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0039/english.txt

SHA-256: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
The codec checks that digest before using the list. This is an executable
proposal, not an accepted format. BIP-39 wallet PBKDF2 seeds are not Hum keys.
