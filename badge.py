#!/usr/bin/env python3
"""GlyphSafe badges (v2): seats badge in with a signed permission slip.

First law: a badge is idempotent to anything vital. Default capabilities are
read-only or undoable. A vital capability (vital:<action>) needs its own slip,
signed by a human for exactly one action.

  badge.py issue  <issuer.key> <seat.pub> <days> <cap> [cap...]  > seat.badge
  badge.py check  <seat.badge> <issuer.pub> [cap] [ledger]       exits 0 if allowed
  badge.py revoke <ledger> <issuer.key> <badge-id>               appends a revocation

The issuer (Hunter's root seat) signs with Ed25519 and ML-DSA-65; both must
verify. Revocations live in the same append-only GlyphSafe ledger, so a lost
phone takes one line to fix.
"""
import json, os, sys, time, base64, hashlib
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

def issue(keyfile, seatpub, days, caps):
    k, s = gs.load(keyfile), gs.load(seatpub)
    vital = [c for c in caps if c.startswith("vital:")]
    if vital and float(days) > 1:
        sys.exit("vital capabilities are single-action slips: use days <= 1, one per slip")
    now = int(time.time())
    slip = {"v": 2, "iss": k["seat"], "sub": s["seat"], "sub_id": s["id"], "caps": sorted(caps),
            "nbf": now, "exp": now + int(float(days) * 86400), "nonce": os.urandom(8).hex()}
    msg = gs.canon(slip)
    slip_id = gs.sha(msg)
    badge = {**slip, "id": slip_id, "sigil": gs.sigil(slip_id), "sig": _sign(k, msg)}
    print(json.dumps(badge, ensure_ascii=False, indent=1))

def revoked(ledger, badge_id, issuer):
    """Only the issuer can revoke its badges; a forged revocation line is ignored."""
    if not ledger: return False
    for e in gs.entries(ledger):
        if e.get("body", {}).get("revoke") != badge_id or e.get("seat") != issuer["seat"]: continue
        core = {x: e[x] for x in ("seq", "time", "seat", "prev", "body")}
        h, h3 = gs.sha(gs.canon(core)), gs.sha3(gs.canon(core))
        try:
            if h == e["hash"] and h3 == e["hash3"]:
                _verify(issuer, e["sig"], (h + h3).encode()); return True
        except Exception: pass
    return False

def check(badgefile, issuerpub, cap=None, ledger=None):
    b, p = gs.load(badgefile), gs.load(issuerpub)
    slip = {x: b[x] for x in ("v", "iss", "sub", "sub_id", "caps", "nbf", "exp", "nonce")}
    msg, now, why = gs.canon(slip), time.time(), []
    if gs.sha(msg) != b["id"]: why.append("badge altered")
    if b["iss"] != p["seat"]: why.append("wrong issuer")
    try: _verify(p, b["sig"], msg)
    except Exception: why.append("signature invalid")
    if not (b["nbf"] <= now < b["exp"]): why.append("expired or not yet valid")
    if revoked(ledger, b["id"], p): why.append("revoked")
    if cap:
        ok_cap = cap in b["caps"] or any(c.endswith("*") and cap.startswith(c[:-1]) for c in b["caps"]
                                         if not c.startswith("vital:"))
        if cap.startswith("vital:") and cap not in b["caps"]: ok_cap = False
        if not ok_cap: why.append(f"not permitted: {cap}")
    verdict = "BADGED IN ∴Ω⧂" if not why else "DENIED: " + ", ".join(why)
    print(f"{b['sub']} by {b['iss']}  {b['sigil']}  {verdict}")
    return not why

def revoke(ledger, keyfile, badge_id):
    k = gs.load(keyfile)
    # revocation is an ordinary signed ledger entry whose body names the badge
    es = gs.entries(ledger)
    prev = es[-1]["hash"] if es else gs.GENESIS
    core = {"seq": len(es), "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seat": k["seat"], "prev": prev, "body": {"revoke": badge_id}}
    h, h3 = gs.sha(gs.canon(core)), gs.sha3(gs.canon(core))
    with open(ledger, "a", encoding="utf-8") as f:
        f.write(json.dumps({**core, "hash": h, "hash3": h3, "sig": _sign(k, (h + h3).encode())},
                           ensure_ascii=False) + "\n")
    print(f"revoked {gs.sigil(badge_id)}  in entry #{core['seq']}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(0)
    if a[0] == "issue": issue(a[1], a[2], a[3], a[4:])
    elif a[0] == "check": sys.exit(0 if check(a[1], a[2], a[3] if len(a) > 3 else None, a[4] if len(a) > 4 else None) else 1)
    elif a[0] == "revoke": revoke(a[1], a[2], a[3])
    else: print(__doc__); sys.exit(2)
