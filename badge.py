#!/usr/bin/env python3
"""GlyphSafe badges (v2.1): seats badge in with a signed permission slip.

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
  operation, consumed by a signed ledger entry. A second use is refused.
"""
import json, os, sys, time
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

FIELDS = ("v", "iss", "sub", "sub_id", "caps", "nbf", "exp", "nonce", "op")

def _slip(k, s, days, caps, op=None):
    now = int(time.time())
    slip = {"v": 2.1, "iss": k["seat"], "sub": s["seat"], "sub_id": s["id"], "caps": sorted(caps),
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

def prove(seatkey, badgefile, challenge):
    k, b = gs.load(seatkey), gs.load(badgefile)
    msg = gs.canon({"badge": b["id"], "challenge": challenge})
    print(json.dumps({"badge": b["id"], "seat": k["seat"], "sig": _sign(k, msg)}))

def _entry_ok(e, signer):
    core = {x: e[x] for x in ("seq", "time", "seat", "prev", "body")}
    h, h3 = gs.sha(gs.canon(core)), gs.sha3(gs.canon(core))
    if h != e["hash"] or h3 != e.get("hash3") or e["seat"] != signer["seat"]: return False
    try: _verify(signer, e["sig"], (h + h3).encode()); return True
    except Exception: return False

def _ledger_state(ledger, anchorfile, issuer):
    """Return (entries, None) if the ledger is whole and not rolled back, else (None, reason)."""
    if not ledger or not os.path.exists(ledger): return None, "trust ledger missing"
    if not anchorfile or not os.path.exists(anchorfile): return None, "anchor missing"
    a = gs.load(anchorfile)
    try: _verify(issuer, a["sig"], gs.canon({"seq": a["seq"], "hash": a["hash"]}))
    except Exception: return None, "anchor signature invalid"
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
          consume_key=None):
    b, p, s = gs.load(badgefile), gs.load(issuerpub), gs.load(seatpub)
    slip = {x: b.get(x) for x in FIELDS}
    msg, now, why = gs.canon(slip), time.time(), []
    if gs.sha(msg) != b["id"]: why.append("badge altered")
    if b["iss"] != p["seat"]: why.append("wrong issuer")
    try: _verify(p, b["sig"], msg)
    except Exception: why.append("signature invalid")
    if s["id"] != b["sub_id"] or s["seat"] != b["sub"]: why.append("seat key doesn't match badge")
    try:
        pr = gs.load(prooffile)
        _verify(s, pr["sig"], gs.canon({"badge": b["id"], "challenge": challenge}))
    except Exception: why.append("no proof of seat key")
    if not (b["nbf"] <= now < b["exp"]): why.append("expired or not yet valid")
    es, err = _ledger_state(ledger, anchorfile, p)
    if err: why.append(err)
    elif any(e["body"].get("revoke") == b["id"] and _entry_ok(e, p) for e in es): why.append("revoked")
    # capability match
    if cap.startswith("vital:"):
        if b["caps"] != [cap]: why.append(f"not permitted: {cap}")
        elif not operation or gs.sha(operation.encode()) != b["op"]: why.append("operation doesn't match slip")
        elif es and any(e["body"].get("consume") == b["id"] for e in es): why.append("vital slip already used")
    elif "as=" in cap:
        if cap not in b["caps"] or cap.split("as=", 1)[1] != b["sub"]: why.append(f"not permitted: {cap}")
    elif not (cap in b["caps"] or any(c.endswith("*") and "as=" not in c and cap.startswith(c[:-1])
                                      for c in b["caps"])):
        why.append(f"not permitted: {cap}")
    ok = not why
    if ok and cap.startswith("vital:") and consume_key:
        k = gs.load(consume_key)
        _append(ledger, k, {"consume": b["id"], "op": b["op"]})
        with open(anchorfile, "w") as f: json.dump(_anchor(ledger, k), f)
    print(f"{b['sub']} by {b['iss']}  {b['sigil']}  {'BADGED IN ∴Ω⧂' if ok else 'DENIED: ' + ', '.join(why)}")
    return ok

def revoke(ledger, keyfile, badge_id, anchorfile="trust.anchor"):
    k = gs.load(keyfile)
    seq = _append(ledger, k, {"revoke": badge_id})
    with open(anchorfile, "w") as f: json.dump(_anchor(ledger, k), f)
    print(f"revoked {gs.sigil(badge_id)} in entry #{seq}; anchor moved to #{seq}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(0)
    c = a[0]
    if c == "issue": issue(a[1], a[2], a[3], a[4:])
    elif c == "vital": vital(a[1], a[2], a[3], a[4])
    elif c == "prove": prove(a[1], a[2], a[3])
    elif c == "check":
        consume = os.environ.get("GLYPHSAFE_CONSUME_KEY")
        sys.exit(0 if check(*a[1:9], a[9] if len(a) > 9 else None, consume_key=consume) else 1)
    elif c == "revoke": revoke(a[1], a[2], a[3], a[4] if len(a) > 4 else "trust.anchor")
    elif c == "anchor":
        print(json.dumps(_anchor(a[1], gs.load(a[2]))))
    else: print(__doc__); sys.exit(2)
