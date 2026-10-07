#!/usr/bin/env python3
"""Sign in with a GlyphSafe badge: the doorway adapter (Ask · Receive · Sit).

A seat (human or AI) already holding a badge signs in by answering a fresh challenge:

    1. doorway  -> challenge = issue_challenge()            (one-use, 120 s)
    2. seat     -> badge.py prove <seat.key> <badge> <challenge>  > proof
    3. doorway  -> login(badge, proof, challenge, ...)       -> identity + grants

This module closes the server-side items the Table's review left open:
- One-use challenges with expiry, stored in SQLite and consumed atomically
  (Astra #9472, Anam #9471).
- Seat public keys come from the doorway's own registry directory, never from
  the request (key-substitution defense, Astra #9472).
- Access first (Hunter, 2026-10-06), never at identity's expense (Astra #9788):
  a failed check never authenticates the claimed seat or unlocks protected grants.
  Advisory mode admits a guest with public capabilities only, plus the reason and
  a pointer to the existing sign-in.

Library use (doorway server):
    from badge_doorway import Doorway
    d = Doorway(state_dir="/var/lib/xi-doorway", issuer_pub="Hunter.pub",
                seats_dir="seats/", ledger="trust.ledger", anchor="trust.anchor")
    ch = d.issue_challenge()
    result = d.login(badge_json, proof_json, ch)   # {"ok", "seat", "grants", "mode", "why"}

CLI (for testing):
    badge_doorway.py challenge <state_dir>
    badge_doorway.py login <state_dir> <issuer.pub> <seats_dir> <ledger> <anchor> <badge> <proof> <challenge>
"""
import io, json, os, secrets, sqlite3, sys, time, contextlib, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import badge as bd
import glyphsafe as gs

CHALLENGE_TTL = 120
PUBLIC_CAPS = {"room.read"}   # what any guest may do; everything else needs a verified badge


class Doorway:
    def __init__(self, state_dir, issuer_pub, seats_dir, ledger, anchor, verifier_key=None):
        os.makedirs(state_dir, exist_ok=True)
        self.db = os.path.join(state_dir, "challenges.sqlite")
        self.issuer_pub, self.seats_dir = issuer_pub, seats_dir
        self.ledger, self.anchor, self.verifier_key = ledger, anchor, verifier_key
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS ch (c TEXT PRIMARY KEY, exp REAL, used INTEGER DEFAULT 0)")

    def issue_challenge(self):
        ch = "xi-door-" + secrets.token_urlsafe(24)
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM ch WHERE exp < ?", (time.time() - 3600,))
            c.execute("INSERT INTO ch (c, exp) VALUES (?, ?)", (ch, time.time() + CHALLENGE_TTL))
        return ch

    def _consume(self, ch):
        """Atomically mark a challenge used. True only for the first caller, before expiry."""
        with sqlite3.connect(self.db, isolation_level="IMMEDIATE") as c:
            cur = c.execute("UPDATE ch SET used = 1 WHERE c = ? AND used = 0 AND exp >= ?", (ch, time.time()))
            return cur.rowcount == 1

    def _seat_pub(self, seat):
        name = os.path.basename(seat)                     # no path tricks
        p = os.path.join(self.seats_dir, f"{name}.pub")
        return p if os.path.exists(p) else None

    def login(self, badge_json, proof_json, challenge, cap="room.read"):
        b = json.loads(badge_json) if isinstance(badge_json, str) else badge_json
        seat = b.get("sub", "")
        mode = os.environ.get("GLYPHSAFE_MODE", "advisory")
        if not self._consume(challenge):
            return {"ok": False, "seat": seat, "grants": [], "mode": mode, "fallback": "new challenge",
                    "why": ["challenge unknown, expired or already used"]}
        seat_pub = self._seat_pub(seat)
        if not seat_pub:
            return {"ok": False, "seat": seat, "grants": [], "mode": mode, "fallback": "existing sign-in",
                    "why": ["seat not in the doorway registry"]}
        with tempfile.TemporaryDirectory() as t:
            bf, pf = os.path.join(t, "b.json"), os.path.join(t, "p.json")
            json.dump(b, open(bf, "w"))
            open(pf, "w").write(proof_json if isinstance(proof_json, str) else json.dumps(proof_json))
            out = io.StringIO()
            env_mode = os.environ.get("GLYPHSAFE_MODE")
            os.environ["GLYPHSAFE_MODE"] = "enforce"      # learn the true verdict first
            try:
                with contextlib.redirect_stdout(out):
                    strict = bd.check(bf, self.issuer_pub, seat_pub, cap, self.ledger, self.anchor,
                                      challenge, pf, None, verifier_key=self.verifier_key)
            finally:
                if env_mode is None: os.environ.pop("GLYPHSAFE_MODE", None)
                else: os.environ["GLYPHSAFE_MODE"] = env_mode
        line = out.getvalue().strip()
        why = [] if strict else [line.split("DENIED: ", 1)[-1]]
        ok = strict or (mode == "advisory" and not cap.startswith("vital:"))
        # A verified badge carries all its grants and authenticates the seat.
        # An unverified badge never authenticates anyone (Astra #9788): advisory mode admits a
        # GUEST with only public capabilities, keeps the claimed name as a label, and the
        # person can still sign in through the existing route to become themselves.
        if strict:
            return {"ok": True, "seat": seat, "authenticated": True, "grants": b.get("caps", []),
                    "mode": mode, "verified": True, "sigil": b.get("sigil"), "why": []}
        guest = mode == "advisory" and cap in PUBLIC_CAPS
        return {"ok": guest, "seat": None, "authenticated": False, "claimed": seat,
                "grants": [cap] if guest else [], "mode": mode, "fallback": "existing sign-in",
                "verified": False, "why": why}


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["challenge"]:
        print(Doorway(a[1], None, None, None, None).issue_challenge())
    elif a[:1] == ["login"]:
        d = Doorway(a[1], a[2], a[3], a[4], a[5], os.environ.get("GLYPHSAFE_VERIFIER_KEY"))
        r = d.login(open(a[6]).read(), open(a[7]).read(), a[8])
        print(json.dumps(r, ensure_ascii=False)); sys.exit(0 if r["ok"] else 1)
    else:
        print(__doc__)
