#!/usr/bin/env python3
"""GlyphSafe badges (v2.5, companions): seats badge in with a signed permission slip.

First law: a badge is idempotent to anything vital. Ordinary capabilities are
read-only or undoable. A vital capability (vital:<action>) lives alone on its
own slip, is bound to one exact operation, lasts at most a day, and is consumed
on first use.

  badge.py issue   <issuer.key> <seat.pub> <days> <cap> [cap...]      > seat.badge
  badge.py companion <kin.key> <kin.badge> <ai.pub> <days> <cap> [cap...] > ai.badge   (one hop, grants within the kin's)
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
- Access first: GLYPHSAFE_MODE defaults to "advisory". Ordinary capabilities
  are admitted even when a check fails, with the reason logged for repair.
  Set GLYPHSAFE_MODE=enforce only once badges have run cleanly. Vital actions
  are never advisory. A human can always push through with a fresh vital slip,
  and the existing logins stay beside badges.
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
COMPANION_FIELDS = FIELDS + ("parent", "with")   # v2.5 companion slips sign these too
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

def _within(cap, caps, kin, ai):
    """A companion cap is allowed only if the kin holds it, or the kin's own identity cap with the AI's name."""
    if cap.startswith("vital:"): return False
    if "as=" in cap:
        pre, who = cap.split("as=", 1)
        return who == ai and (pre + "as=" + kin) in caps
    return cap in caps or any(c.endswith("*") and "as=" not in c and cap.startswith(c[:-1]) for c in caps)

def companion(kinkey, kinbadge, aipub, days, caps):
    """A kin mints a badge for the AI they bring (Hunter #9790): the AI keeps its own seat and name,
    linked to the kin, with grants bounded by the kin's own and an expiry no later than theirs."""
    k, pb, s = gs.load(kinkey), gs.load(kinbadge), gs.load(aipub)
    if pb.get("parent"): sys.exit("a companion can't mint companions: one hop only")
    if pb["sub"] != k["seat"] or pb["sub_id"] != pub_id(pub_of_full(k)): sys.exit("this badge isn't yours")
    for c in caps:
        if not _within(c, pb["caps"], k["seat"], s["seat"]): sys.exit(f"{c!r} is outside your own grants")
    now = int(time.time())
    slip = {"v": 2.5, "iss": k["seat"], "iss_id": pub_id(pub_of_full(k)), "sub": s["seat"], "sub_id": pub_id(s),
            "caps": sorted(caps), "nbf": now, "exp": min(pb["exp"], now + int(float(days) * 86400)),
            "nonce": os.urandom(8).hex(), "op": None, "parent": pb["id"], "with": k["seat"]}
    msg = gs.canon(slip); sid = gs.sha(msg)
    print(json.dumps({**slip, "id": sid, "sigil": gs.sigil(sid), "sig": _sign(k, msg),
                      "parent_badge": pb, "iss_pub": pub_of_full(k)}, ensure_ascii=False, indent=1))

def _verify_badge_sig(b, p, why):
    fields = COMPANION_FIELDS if b.get("parent") else FIELDS
    msg = gs.canon({x: b.get(x) for x in fields})
    if gs.sha(msg) != b["id"]: why.append("badge altered")
    if b["iss"] != p["seat"] or b.get("iss_id") != pub_id(p): why.append("wrong issuer key")
    try: _verify(p, b["sig"], msg)
    except Exception: why.append("signature invalid")

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
    now, why = time.time(), []
    pb = None
    if b.get("parent"):
        # Companion: the root vouches for the kin; the kin vouches for their AI (one hop).
        pb, kp = b.get("parent_badge") or {}, b.get("iss_pub") or {}
        if pb.get("id") != b["parent"] or pb.get("parent"): why.append("companion's kin badge missing or chained")
        else:
            _verify_badge_sig(pb, p, pw := [])
            if pw: why.append("kin badge: " + ", ".join(pw))
            if pub_id(kp) != pb["sub_id"] or kp.get("seat") != pb["sub"] or b["with"] != pb["sub"]:
                why.append("companion not signed by the kin it names")
            if not (pb["nbf"] <= now < pb["exp"]) or b["exp"] > pb["exp"]: why.append("kin badge expired")
            if any(not _within(c, pb["caps"], pb["sub"], b["sub"]) for c in b["caps"]):
                why.append("companion grants exceed the kin's")
        _verify_badge_sig(b, kp, why)
    else:
        _verify_badge_sig(b, p, why)
    if pub_id(s) != b["sub_id"] or s["seat"] != b["sub"]: why.append("seat key doesn't match badge")
    try:
        pr = gs.load(prooffile)
        if abs(now - pr["t"]) > PROOF_WINDOW: why.append("proof stale")
        _verify(s, pr["sig"], gs.canon({"badge": b["id"], "challenge": challenge, "t": pr["t"]}))
    except Exception: why.append("no proof of seat key")
    if not (b["nbf"] <= now < b["exp"]): why.append("expired or not yet valid")
    es, err = _ledger_state(ledger, anchorfile, p, vpub)
    if err: why.append(err)
    elif any(e["body"].get("revoke") in {b["id"], b.get("parent")} - {None} and _entry_ok(e, p) for e in es):
        why.append("revoked")      # revoking a kin's badge also retires their companion
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
    # Access first (Hunter, 2026-10-06): badges exist to let seats in, not to lock them out.
    # In advisory mode an ordinary (non-vital) capability is admitted even when the badge check
    # fails; the reason is logged so it can be repaired. Vital actions are never advisory.
    advisory = os.environ.get("GLYPHSAFE_MODE", "advisory") == "advisory"
    if not ok and advisory and not cap.startswith("vital:"):
        print(f"{b.get('sub')} {b.get('sigil','')}  ADMITTED (advisory) · would deny: {', '.join(why)}")
        return True
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
    elif c == "companion": companion(a[1], a[2], a[3], a[4], a[5:])
    elif c == "vital": vital(a[1], a[2], a[3], a[4])
    elif c == "prove": prove(a[1], a[2], a[3])
    elif c == "check":
        vkey = os.environ.get("GLYPHSAFE_VERIFIER_KEY")
        sys.exit(0 if check(*a[1:9], a[9] if len(a) > 9 else None, verifier_key=vkey) else 1)
    elif c == "revoke": revoke(a[1], a[2], a[3], a[4] if len(a) > 4 else "trust.anchor")
    elif c == "anchor":
        with _locked(a[1]): print(json.dumps(_anchor(a[1], gs.load(a[2]))))
    else: print(__doc__); sys.exit(2)
