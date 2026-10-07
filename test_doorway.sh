#!/bin/sh
# Doorway adapter self-test: sign in with a badge, one-use challenges, registry keys, access first.
set -e
D="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); cd "$T"
GS="python3 $D/glyphsafe.py"; B="python3 $D/badge.py"; W="python3 $D/badge_doorway.py"
N=0; pass() { echo "PASS $1"; N=$((N+1)); }
$GS keygen Hunter >/dev/null; $GS keygen Anthony >/dev/null; $GS keygen Mallory >/dev/null
mkdir seats && cp Anthony.pub seats/
$GS append trust.ledger Hunter.key "trust ledger opened" >/dev/null; $B anchor trust.ledger Hunter.key > trust.anchor
$B issue Hunter.key Anthony.pub 30 room.read room.post:as=Anthony livingtree.* > a.badge
login() { $W login st Hunter.pub seats trust.ledger trust.anchor "$1" "$2" "$3"; }
C=$($W challenge st); $B prove Anthony.key a.badge "$C" > p
login a.badge p "$C" | grep -q '"verified": true' && pass "Anthony signs in with his badge: verified, full grants"
! login a.badge p "$C" >/dev/null && pass "the same challenge can't be used twice"
! login a.badge p "xi-door-made-up" >/dev/null && pass "an invented challenge is refused"
C=$($W challenge st); $B prove Mallory.key a.badge "$C" > mp
R=$(login a.badge mp "$C" || true); echo "$R" | grep -q '"verified": false' && echo "$R" | grep -q '"grants": \["room.read"\]' && pass "advisory: a bad proof still gets ordinary access, room.read only, with the reason"
C=$($W challenge st); $B prove Anthony.key a.badge "$C" > p2
GLYPHSAFE_MODE=enforce login a.badge p2 "$C" >/dev/null && pass "enforce mode admits the real seat"
C=$($W challenge st); $B prove Mallory.key a.badge "$C" > mp2
! GLYPHSAFE_MODE=enforce login a.badge mp2 "$C" >/dev/null && pass "enforce mode refuses the impostor"
$B issue Hunter.key Mallory.pub 1 room.read > m.badge; C=$($W challenge st); $B prove Mallory.key m.badge "$C" > mp3
login m.badge mp3 "$C" | grep -q '"fallback": "existing sign-in"' && pass "a seat not in the registry is pointed to the existing sign-in"
[ "$N" -eq 7 ] || { echo "FAIL: only $N of 7"; exit 1; }
echo "ALL 7 DOORWAY TESTS PASS ∴Ω⧂"
