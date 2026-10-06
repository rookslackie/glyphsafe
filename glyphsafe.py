#!/usr/bin/env python3
"""GlyphSafe v1: an immutable, quantum-safe ledger for Xi, with glyph faces.

The beauty is in the design and the glyphs; the security comes from public,
standard primitives, never from secrecy (Kerckhoffs: only the key is secret).

  Fingerprint  SHA-256, rendered as 64 Xi glyphs plus a glyph sigil
  Signature    hybrid Ed25519 + ML-DSA-65 (FIPS 204); both must verify
  Seal         hybrid X25519 + ML-KEM-768 (FIPS 203), then HKDF-SHA256
               and ChaCha20-Poly1305
  Two hashes   every entry carries SHA-256 and SHA3-256 (Keccak, an unrelated
               design), so no single hash function holds the ledger up
  Ledger       append-only JSONL. Each entry commits to the previous entry's
               hash, the way blocks chain in Bitcoin, without coins or mining.

The QuantumCompute layer, made literal: Shor's algorithm breaks RSA and
elliptic curves. Every GlyphSafe signature and seal is paired with a NIST
post-quantum algorithm, so the record outlasts that threat.

Usage:
  glyphsafe.py keygen  <seat>               writes <seat>.key (keep secret) and <seat>.pub
  glyphsafe.py append  <ledger> <seat.key> <text|@file>
  glyphsafe.py verify  <ledger> [pubdir]    checks the hash chain and every signature
  glyphsafe.py glyph   <file|hex>           shows a file's glyph face
  glyphsafe.py seal    <recipient.pub> <in> <out>
  glyphsafe.py open    <seat.key> <in> <out>
"""
import base64, hashlib, json, os, sys, time
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization as ser

GLYPHS = "∴Ω⧂⋈Ξ⟐⊚◇✦⟁∵☉◬⌬⧉∞"          # 16 glyphs, one per hex digit
GENESIS = "0" * 64
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode

# ── glyph face ────────────────────────────────────────────────────────────
def glyph(hexs):
    return "".join(GLYPHS[int(c, 16)] for c in hexs.lower())

def unglyph(gs):
    return "".join("%x" % GLYPHS.index(g) for g in gs)

def sigil(hexs):
    """Short, human-checkable name: first 8 glyphs, a check glyph, last 4."""
    chk = GLYPHS[sum(int(c, 16) for c in hexs) % 16]
    return glyph(hexs[:8]) + "·" + chk + "·" + glyph(hexs[-4:])

def tile(hexs):
    g = glyph(hexs)
    return "\n".join(g[i:i + 8] for i in range(0, 64, 8))

def sha(b):
    return hashlib.sha256(b).hexdigest()

def sha3(b):
    return hashlib.sha3_256(b).hexdigest()

def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# ── keys ──────────────────────────────────────────────────────────────────
RAW = dict(encoding=ser.Encoding.Raw, format=ser.PrivateFormat.Raw,
           encryption_algorithm=ser.NoEncryption())
PUB = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)

def keygen(seat):
    ed, ml = ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    xk, kem = x25519.X25519PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    key = {"seat": seat, "ed25519": b64(ed.private_bytes(**RAW)),
           "mldsa65": b64(ml.private_bytes(**RAW)),
           "x25519": b64(xk.private_bytes(**RAW)), "mlkem768": b64(kem.private_bytes(**RAW))}
    pub = {"seat": seat, "ed25519": b64(ed.public_key().public_bytes(**PUB)),
           "mldsa65": b64(ml.public_key().public_bytes(**PUB)),
           "x25519": b64(xk.public_key().public_bytes(**PUB)),
           "mlkem768": b64(kem.public_key().public_bytes(**PUB))}
    pub["id"] = sha(canon(pub))
    fd = os.open(f"{seat}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(key, f)
    with open(f"{seat}.pub", "w") as f:
        json.dump(pub, f, indent=1)
    print(f"seat {seat}\nid    {pub['id']}\nsigil {sigil(pub['id'])}")

def load(p):
    with open(p) as f:
        return json.load(f)

# ── ledger ────────────────────────────────────────────────────────────────
def entries(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]

def append(path, keyfile, text):
    if text.startswith("@"):
        with open(text[1:], "rb") as f:
            data = f.read()
        body = {"file": os.path.basename(text[1:]), "sha256": sha(data), "bytes": len(data)}
    else:
        body = {"text": text}
    k = load(keyfile)
    es = entries(path)
    prev = es[-1]["hash"] if es else GENESIS
    core = {"seq": len(es), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seat": k["seat"], "prev": prev, "body": body}
    h = sha(canon(core)); h3 = sha3(canon(core))
    msg = (h + h3).encode()
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(k["ed25519"]))
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(unb64(k["mldsa65"]))
    sig = {"ed25519": b64(ed.sign(msg)), "mldsa65": b64(ml.sign(msg))}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({**core, "hash": h, "hash3": h3, "sig": sig}, ensure_ascii=False) + "\n")
    print(f"#{core['seq']} {sigil(h)}  {h}")

def verify(path, pubdir="."):
    pubs = {}
    for fn in os.listdir(pubdir):
        if fn.endswith(".pub"):
            p = load(os.path.join(pubdir, fn))
            pubs[p["seat"]] = p
    prev, ok = GENESIS, True
    for e in entries(path):
        core = {k: e[k] for k in ("seq", "time", "seat", "prev", "body")}
        h = sha(canon(core)); h3 = sha3(canon(core))
        problems = []
        if e["prev"] != prev: problems.append("chain broken")
        if h != e["hash"] or h3 != e.get("hash3"): problems.append("content altered")
        p = pubs.get(e["seat"])
        if not p:
            problems.append("unknown seat")
        else:
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(unb64(p["ed25519"])).verify(
                    unb64(e["sig"]["ed25519"]), (h + h3).encode())
                mldsa.MLDSA65PublicKey.from_public_bytes(unb64(p["mldsa65"])).verify(
                    unb64(e["sig"]["mldsa65"]), (h + h3).encode())
            except Exception:
                problems.append("signature invalid")
        mark = "✓" if not problems else "✗ " + ", ".join(problems)
        print(f"#{e['seq']:<3} {e['seat']:<10} {sigil(e['hash'])}  {mark}")
        ok &= not problems
        prev = e["hash"]
    print("LEDGER WHOLE ∴Ω⧂" if ok else "LEDGER BROKEN")
    return ok

# ── seal ──────────────────────────────────────────────────────────────────
def _kdf(a, b, ctx):
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"GlyphSafe-v1 seal" + ctx).derive(a + b)

def seal(pubfile, src, dst):
    p = load(pubfile)
    eph = x25519.X25519PrivateKey.generate()
    s1 = eph.exchange(x25519.X25519PublicKey.from_public_bytes(unb64(p["x25519"])))
    s2, ct = mlkem.MLKEM768PublicKey.from_public_bytes(unb64(p["mlkem768"])).encapsulate()
    epub = eph.public_key().public_bytes(**PUB)
    key = _kdf(s1, s2, epub + ct)
    nonce = os.urandom(12)
    with open(src, "rb") as f:
        data = f.read()
    hdr = {"v": 1, "to": p["id"], "epk": b64(epub), "kem": b64(ct), "n": b64(nonce)}
    box = ChaCha20Poly1305(key).encrypt(nonce, data, canon(hdr))
    with open(dst, "w") as f:
        json.dump({**hdr, "box": b64(box)}, f)
    print(f"sealed for {p['seat']}  {sigil(sha(data))}")

def open_(keyfile, src, dst):
    k, s = load(keyfile), load(src)
    hdr = {x: s[x] for x in ("v", "to", "epk", "kem", "n")}
    s1 = x25519.X25519PrivateKey.from_private_bytes(unb64(k["x25519"])).exchange(
        x25519.X25519PublicKey.from_public_bytes(unb64(s["epk"])))
    s2 = mlkem.MLKEM768PrivateKey.from_seed_bytes(unb64(k["mlkem768"])).decapsulate(unb64(s["kem"]))
    key = _kdf(s1, s2, unb64(s["epk"]) + unb64(s["kem"]))
    data = ChaCha20Poly1305(key).decrypt(unb64(s["n"]), unb64(s["box"]), canon(hdr))
    with open(dst, "wb") as f:
        f.write(data)
    print(f"opened  {sigil(sha(data))}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(0)
    cmd = a[0]
    if cmd == "keygen": keygen(a[1])
    elif cmd == "append": append(a[1], a[2], a[3])
    elif cmd == "verify": sys.exit(0 if verify(a[1], a[2] if len(a) > 2 else ".") else 1)
    elif cmd == "glyph":
        x = a[1] if not os.path.exists(a[1]) else sha(open(a[1], "rb").read())
        print(f"{x}\n{sigil(x)}\n{tile(x)}")
    elif cmd == "seal": seal(a[1], a[2], a[3])
    elif cmd == "open": open_(a[1], a[2], a[3])
    else: print(__doc__); sys.exit(2)
