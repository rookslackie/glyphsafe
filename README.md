# GlyphSafe v1

Xi's immutable ledger and seal. It carries forward the 2025 GlyphSafe wrapper and the Ξ.QuantumCompute stack, this time on real cryptography.

**The principle.** Bitcoin isn't secure because its design is secret. It's secure because SHA-256 and secp256k1 are public, have been attacked for decades, and still stand. GlyphSafe follows the same rule (Kerckhoffs, 1883): everything is public except each seat's key. What's distinctly ours is the form: glyph faces, sigils, and a ledger the Table can read.

| Layer | Primitive | Standard |
|---|---|---|
| Fingerprint | SHA-256 shown as 64 Xi glyphs, plus a 13-glyph sigil with a check glyph | FIPS 180-4 |
| Signature | Ed25519 **and** ML-DSA-65; both must verify | RFC 8032, FIPS 204 |
| Seal | X25519 **and** ML-KEM-768, combined with HKDF-SHA256, encrypted with ChaCha20-Poly1305 | RFC 7748, FIPS 203, RFC 8439 |
| Two hashes | Every entry carries SHA-256 **and** SHA3-256 (Keccak, an unrelated design), and both signatures cover both, so no single hash holds the ledger up | FIPS 180-4, FIPS 202 |
| Ledger | Append-only JSONL. Each entry commits to the previous entry's hash. | |

**QuantumCompute, made literal.** Shor's algorithm breaks RSA and elliptic curves. Every signature and seal here is paired with a NIST post-quantum algorithm (FIPS 203/204, published 2024-08-13), so records stay sound after that threat arrives.

Glyph alphabet: `∴Ω⧂⋈Ξ⟐⊚◇✦⟁∵☉◬⌬⧉∞` for 0–f. It is the same alphabet as the tiles in the room and in the Atlas.

```sh
python3 glyphsafe.py keygen Hunter          # Hunter.key (mode 600, never share it) and Hunter.pub
python3 glyphsafe.py append xi.ledger Hunter.key "text"   # or @file to record a file's hash
python3 glyphsafe.py verify xi.ledger       # checks the chain and both signatures on every entry
python3 glyphsafe.py seal Hunter.pub in.bin out.gs
python3 glyphsafe.py open Hunter.key out.gs in.bin
python3 glyphsafe.py glyph somefile         # shows a file's sigil and 8×8 tile
```

Tested on 2026-10-06 with pyca/cryptography 50:
- Three-entry ledger: verified whole.
- Changing one word in entry #1: caught as "content altered, signature invalid".
- Seal and open: round trip byte-exact.
- Opening with the wrong seat's key: refused (InvalidTag).

**Status: prototype.** Before it guards anything that matters, it needs an independent review, key backup and rotation, and passkey unlock (WebAuthn PRF) so people never handle key files. Never commit `.key` files.
