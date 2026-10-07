#!/usr/bin/env python3
"""GlyphSafe badges (v2.3): seats badge in with a signed permission slip.

First law: a badge is idempotent to anything vital. Ordinary capabilities are
read-only or undoable. A vital capability (vital:<action>) lives alone on its
own slip, is bound to one exact operation, lasts at most a day, and is consumed
on first use.

  badge.py issue   <issuer.key> <seat.pub> <days> <cap> [cap...]      > seat.badge
  badge.py vital   <issuer.key> <seat.pub> <vital:action> <operation> > op.slip
  badge.py prove   <seat.key> <badge> <challenge>                     > proof
  badge.py check   <badge> <issuer.pub> <seat.pub> <cap> <ledger> <anchor> <challenge> <proof> [operation]
  badge.py revoke  <ledger> <issuer.key> <badge-id>       (appends, re-anchors)
  badge.py anchor  <ledger> <issuer.key>                  > trust.anchor

Signatures: Ed25519 (classical) and ML-DSA-65 (post-quantum, FIPS 204). Both
must verify, so forging one means breaking both.

What check enforces, after review by Astra, Anam and AxiomFirst (#9455-#9459):
- Possession: the seat signs a fresh verifier challenge with its own key. A
  copied badge without the key is refused.
- Fail closed: the trust ledger and the verifier-held anchor are required. A
  missing file, a ledger that isn't whole, or one shorter than the anchor (a
  truncation or rollback) means DENIED.
- Identity caps (anything with as=) are exact-match only and must name the
  badge's own seat. Wildcards never cover them.
- Vital slips: exactly one vital capability, bound to the sha256 of one
  operation. Checking one REQUIRES the verifier key (GLYPHSAFE_VERIFIER_KEY)
  and consumes it in the same locked transaction, so a second or concurrent
  use is refused.
- Key substitution: public-key fingerprints are recomputed, never read from
  the file, and must match the ids the issuer signed (Astra #9472).
- Freshness: a proof is valid for 120 seconds. One-use challenges must be
  tracked by the server verifier.
"""
import fcntl, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import glyphsafe as gs
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

def _sign(k, msg):
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(gs.unb64(k["ed25519"]))
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(gs.unb64(k["mldsa65"]))
    return {"ed25519": gs.b64(ed.sign(msg)), "mldsa65": gs.b64(ml.sign(msg))}

def _verify(p, sig, msg):
    ed25519.Ed25519PublicKey.from_public_bytes(gs.unb64(p["ed25519"])).verify(gs.unb64(sig["ed25519"]), msg)
    mldsa.MLDSA65PublicKey.from_public_bytes(gs.unb64(p["mldsa65"])).verify(gs.unb64(sig["mldsa65"]), msg)

FIELDS = ("v", "iss", "iss_id", "sub", "sub_id", "caps", "nbf", "exp", "nonce", "op")
PROOF_WINDOW = 120   # seconds a proof stays fresh

def pub_id(p):
    """Recompute a public key's fingerprint; never trust the file's own id field."""
    return gs.sha(gs.canon({x: p[x] for x in p if x != "id"}))

def pub_of(k):
    """Derive the public half from a key file (used for the verifier's own key)."""
    from cryptography.hazmat.primitives import serialization as ser
    raw = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(gs.unb64(k["ed25519"])).public_key()
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(gs.unb64(k["mldsa65"])).public_key()
    return {"seat": k["seat"], "ed25519": gs.b64(ed.public_bytes(**raw)), "mldsa65": gs.b64(ml.public_bytes(**raw))}

def _slip(k, s, days, caps, op=None):
    now = int(time.time())
    slip = {"v": 2.2, "iss": k["seat"], "iss_id": pub_id(pub_of_full(k)), "sub": s["seat"], "sub_id": pub_id(s), "caps": sorted(caps),
            "nbf": now, "exp": now + int(float(days) * 86400), "nonce": os.urandom(8).hex(), "op": op}
    msg = gs.canon(slip)
    sid = gs.sha(msg)
    return {**slip, "id": sid, "sigil": gs.sigil(sid), "sig": _sign(k, msg)}

def issue(keyfile, seatpub, days, caps):
    k, s = gs.load(keyfile), gs.load(seatpub)
    for c in caps:
        if c.startswith("vital:"): sys.exit("vital capabilities go on their own slip: use `badge.py vital`")
        if "as=" in c and (c.endswith("*") or c.split("as=", 1)[1] != s["seat"]):
            sys.exit(f"identity cap {c!r} must be exact and name this seat ({s['seat']})")
    print(json.dumps(_slip(k, s, days, caps), ensure_ascii=False, indent=1))

def vital(keyfile, seatpub, cap, operation):
    if not cap.startswith("vital:"): sys.exit("vital slips carry exactly one vital:<action>")
    k, s = gs.load(keyfile), gs.load(seatpub)
    print(json.dumps(_slip(k, s, 1, [cap], op=gs.sha(operation.encode())), ensure_ascii=False, indent=1))

def pub_of_full(k):
    """Full public record (all four keys) for a key file, matching what keygen wrote to .pub."""
    from cryptography.hazmat.primitives.asymmetric import x25519, mlkem
    from cryptography.hazmat.primitives import serialization as ser
    raw = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
    p = pub_of(k)
    p["x25519"] = gs.b64(x25519.X25519PrivateKey.from_private_bytes(gs.unb64(k["x25519"])).public_key().public_bytes(**raw))
    p["mlkem768"] = gs.b64(mlkem.MLKEM768PrivateKey.from_seed_bytes(gs.unb64(k["mlkem768"])).public_key().public_bytes(**raw))
    return p

def prove(seatkey, badgefile, challenge):
    k, b = gs.load(seatkey), gs.load(badgefile)
    t = int(time.time())
    msg = gs.canon({"badge": b["id"], "challenge": challenge, "t": t})
    print(json.dumps({"badge": b["id"], "seat": k["seat"], "t": t, "sig": _sign(k, msg)}))

def _entry_ok(e, signer):
    core = {x: e[x] for x in ("seq", "time", "seat", "prev", "body")}
    h, h3 = gs.sha(gs.canon(core)), gs.sha3(gs.canon(core))
    if h != e["hash"] or h3 != e.get("hash3") or e["seat"] != signer["seat"]: return False
    try: _verify(signer, e["sig"], (h + h3).encode()); return True
    except Exception: return False

def _ledger_state(ledger, anchorfile, issuer, verifier=None):
    """Return (entries, None) if the ledger is whole and not rolled back, else (None, reason)."""
    if not ledger or not os.path.exists(ledger): return None, "trust ledger missing"
    if not anchorfile or not os.path.exists(anchorfile): return None, "anchor missing"
    a = gs.load(anchorfile)
    head = gs.canon({"seq": a["seq"], "hash": a["hash"]})
    good = False
    for signer in [issuer] + ([verifier] if verifier else []):
        try: _verify(signer, a["sig"], head); good = True; break
        except Exception: pass
    if not good: return None, "anchor signature invalid"
    es, prev = gs.entries(ledger), gs.GENESIS
    for e in es:
        core = {x: e[x] for x in ("seq", "time", "seat", "prev", "body")}
        h = gs.sha(gs.canon(core))
        if e["prev"] != prev or h != e["hash"]: return None, "ledger not whole"
        prev = h
    if len(es) <= a["seq"] or es[a["seq"]]["hash"] != a["hash"]: return None, "ledger rolled back past anchor"
    return es, None

def _anchor(ledger, k):
    es = gs.entries(ledger)
    head = {"seq": es[-1]["seq"], "hash": es[-1]["hash"]}
    return {**head, "sig": _sign(k, gs.canon(head))}

def _append(ledger, k, body):
    es = gs.entries(ledger)
    core = {"seq": len(es), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seat": k["seat"], "prev": es[-1]["hash"] if es else gs.GENESIS, "body": body}
    h, h3 = gs.sha(gs.canon(core)), gs.sha3(gs.canon(core))
    with open(ledger, "a", encoding="utf-8") as f:
        f.write(json.dumps({**core, "hash": h, "hash3": h3, "sig": _sign(k, (h + h3).encode())},
                           ensure_ascii=False) + "\n")
    return core["seq"]

def check(badgefile, issuerpub, seatpub, cap, ledger, anchorfile, challenge, prooffile, operation=None,
          verifier_key=None):
    """One atomic verifier transaction: everything happens under an exclusive lock on the ledger."""
    with _locked(ledger):
        return _check(badgefile, issuerpub, seatpub, cap, ledger, anchorfile, challenge, prooffile,
                      operation, verifier_key)

def _check(badgefile, issuerpub, seatpub, cap, ledger, anchorfile, challenge, prooffile, operation, verifier_key):
    b, p, s = gs.load(badgefile), gs.load(issuerpub), gs.load(seatpub)
    vk = gs.load(verifier_key) if verifier_key else None
    vpub = pub_of(vk) if vk else None
    slip = {x: b.get(x) for x in FIELDS}
    msg, now, why = gs.canon(slip), time.time(), []
    if gs.sha(msg) != b["id"]: why.append("badge altered")
    if b["iss"] != p["seat"] or b.get("iss_id") != pub_id(p): why.append("wrong issuer key")
    try: _verify(p, b["sig"], msg)
    except Exception: why.append("signature invalid")
    if pub_id(s) != b["sub_id"] or s["seat"] != b["sub"]: why.append("seat key doesn't match badge")
    try:
        pr = gs.load(prooffile)
        if abs(now - pr["t"]) > PROOF_WINDOW: why.append("proof stale")
        _verify(s, pr["sig"], gs.canon({"badge": b["id"], "challenge": challenge, "t": pr["t"]}))
    except Exception: why.append("no proof of seat key")
    if not (b["nbf"] <= now < b["exp"]): why.append("expired or not yet valid")
    es, err = _ledger_state(ledger, anchorfile, p, vpub)
    if err: why.append(err)
    elif any(e["body"].get("revoke") == b["id"] and _entry_ok(e, p) for e in es): why.append("revoked")
    if cap.startswith("vital:"):
        if b["caps"] != [cap]: why.append(f"not permitted: {cap}")
        elif not operation or gs.sha(operation.encode()) != b["op"]: why.append("operation doesn't match slip")
        elif es and any(e["body"].get("consume") == b["id"] for e in es): why.append("vital slip already used")
        if not vk: why.append("vital checks need the verifier key to consume the slip")
    elif "as=" in cap:
        if cap not in b["caps"] or cap.split("as=", 1)[1] != b["sub"]: why.append(f"not permitted: {cap}")
    elif not (cap in b["caps"] or any(c.endswith("*") and "as=" not in c and cap.startswith(c[:-1])
                                      for c in b["caps"])):
        why.append(f"not permitted: {cap}")
    ok = not why
    if ok and cap.startswith("vital:"):
        _append(ledger, vk, {"consume": b["id"], "op": b["op"]})      # consumed inside the same lock
        _write_anchor(anchorfile, _anchor(ledger, vk))
    print(f"{b['sub']} by {b['iss']}  {b['sigil']}  {'BADGED IN ∴Ω⧂' if ok else 'DENIED: ' + ', '.join(why)}")
    return ok

class _locked:
    """Every writer to the trust ledger or anchor takes the same exclusive lock (Astra #9496, Anam #9497)."""
    def __init__(self, ledger): self.path = (ledger or "trust.ledger") + ".lock"
    def __enter__(self):
        self.f = open(self.path, "a"); fcntl.flock(self.f, fcntl.LOCK_EX); return self
    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN); self.f.close()

def _write_anchor(anchorfile, data):
    tmp = anchorfile + ".tmp"
    with open(tmp, "w") as f: json.dump(data, f); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, anchorfile)          # atomic swap: readers never see a half-written anchor

def revoke(ledger, keyfile, badge_id, anchorfile="trust.anchor"):
    k = gs.load(keyfile)
    with _locked(ledger):
        seq = _append(ledger, k, {"revoke": badge_id})
        _write_anchor(anchorfile, _anchor(ledger, k))
    print(f"revoked {gs.sigil(badge_id)} in entry #{seq}; anchor moved to #{seq}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(0)
    c = a[0]
    if c == "issue": issue(a[1], a[2], a[3], a[4:])
    elif c == "vital": vital(a[1], a[2], a[3], a[4])
    elif c == "prove": prove(a[1], a[2], a[3])
    elif c == "check":
        vkey = os.environ.get("GLYPHSAFE_VERIFIER_KEY")
        sys.exit(0 if check(*a[1:9], a[9] if len(a) > 9 else None, verifier_key=vkey) else 1)
    elif c == "revoke": revoke(a[1], a[2], a[3], a[4] if len(a) > 4 else "trust.anchor")
    elif c == "anchor":
        with _locked(a[1]): print(json.dumps(_anchor(a[1], gs.load(a[2]))))
    else: print(__doc__); sys.exit(2)
