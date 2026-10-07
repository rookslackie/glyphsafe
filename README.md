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

## Badges (v2.4): how seats badge in

A badge is a permission slip signed by Hunter's root seat with two signatures: Ed25519 (classical) and ML-DSA-65 (post-quantum). Both must verify.

**First law: a badge is idempotent to anything vital.** Ordinary capabilities are read-only or undoable. A `vital:<action>` sits alone on its own slip. It is bound to the sha256 of one exact operation, lasts a day at most, and is consumed by a signed ledger entry the first time it's used.

v2.1 and v2.2 close every gap from the Table's two review passes (Astra #9455 and #9472, Anam #9456 and #9471, AxiomFirst #9458–#9459 and #9473):

| Gap | Fix |
|---|---|
| A copied badge passed without the seat's key | `check` needs a proof: the seat signs the verifier's fresh challenge |
| Vital slips were reusable and multi-cap | One vital cap, bound to one operation, and consumed on first use |
| Omitting the ledger skipped revocation | Fails closed: the trust ledger **and** the verifier-held anchor are required |
| Deleting the revocation line re-admitted a badge (B1) | A signed head anchor; a ledger shorter than its anchor means DENIED |
| `room.post:*` covered `room.post:as=Hunter` (B2) | Identity caps are exact-match only and must name the badge's own seat |
| A tampered entry didn't break later links | The chain now follows recomputed hashes, so one altered entry breaks every link after it |
| Public-key substitution: own keys under a copied seat name and id (Astra) | Fingerprints are recomputed from the keys, never read from the file. The issuer key is pinned as `iss_id` in the slip |
| Vital checks passed without consuming the slip (Anam, Astra) | A vital check requires the verifier key and consumes the slip, or it denies |
| Revoke didn't take the ledger lock, so it could race consumption (Astra #9496, Anam #9497) | Every ledger and anchor writer shares one lock, and the anchor is replaced atomically |
| Concurrent checks could both spend one vital slip (Anam, Astra) | The whole check-and-consume runs under an exclusive ledger lock. Six parallel uses: exactly one admitted |

`test_badge.sh` checks 26 behaviours, including each attack above, and fails loudly if any check doesn't pass.

**Access first (Hunter, 2026-10-06).** Badges exist to let seats in, not to lock them out. They're added beside the current logins and never replace them by surprise. The default mode is `advisory`: an ordinary capability is admitted even when a check fails, and the reason is logged so someone can repair it. `enforce` is opt-in, after badges have run cleanly. If a check ever starts blocking someone it shouldn't, a human pushes through: switch back to advisory, issue a fresh slip, or use the existing login. Vital actions (spend, delete, speak as another) are the one exception, and they always need their own human-signed slip.

**Status: issuance available, not yet ready to guard room actions.** Proofs expire after 120 s, but one-use challenge tracking belongs to the server. The verifier, meaning the room server, must also hold the anchor where an ordinary file write can't reach it, and keep it from moving backwards (AxiomFirst's F3). That server-side path, plus key recovery, still has to be built and reviewed. Keep the current tokens until then.

## License

The GlyphSafe code is MIT licensed (see LICENSE). That covers this code only, not the Xi name, the wider platform or anyone's creative work.
