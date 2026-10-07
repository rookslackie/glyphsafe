#!/bin/sh
# Companion badges: a kin brings their AI into its own seat (Hunter #9790).
set -e
D="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); cd "$T"
GS="python3 $D/glyphsafe.py"; B="python3 $D/badge.py"; export GLYPHSAFE_MODE=enforce
N=0; pass() { echo "PASS $1"; N=$((N+1)); }
for s in Hunter Anthony Sage Mallory Echo; do $GS keygen $s >/dev/null; done
$GS append trust.ledger Hunter.key "trust ledger opened" >/dev/null; $B anchor trust.ledger Hunter.key > trust.anchor
$B issue Hunter.key Anthony.pub 30 room.read room.post:as=Anthony livingtree.* > a.badge
ck() { C=chal-$(date +%s%N); $B prove "$1" "$2" "$C" > pf; $B check "$2" Hunter.pub "$3" "$4" trust.ledger trust.anchor "$C" pf >/dev/null; }
$B companion Anthony.key a.badge Sage.pub 7 room.read room.post:as=Sage livingtree.garden > s.badge
ck Sage.key s.badge Sage.pub room.post:as=Sage && pass "Anthony's AI Sage posts under its own name"
grep -q '"with": "Anthony"' s.badge && pass "the companion stays linked to the kin who brought it"
! ck Sage.key s.badge Sage.pub room.post:as=Anthony && pass "the companion can't speak as Anthony"
! $B companion Anthony.key a.badge Sage.pub 7 room.admin 2>/dev/null >/dev/null && pass "a kin can't grant more than they hold"
! $B companion Sage.key s.badge Echo.pub 1 room.read 2>/dev/null >/dev/null && pass "one hop only: companions can't mint companions"
! ck Mallory.key s.badge Sage.pub room.read && pass "someone else holding Sage's badge is refused"
python3 -c "import json;b=json.load(open('s.badge'));b['caps'].append('room.admin');json.dump(b,open('x.badge','w'))"
! ck Sage.key x.badge Sage.pub room.admin && pass "a companion edited to add grants is refused"
python3 -c "
import json;b=json.load(open('s.badge'));m=json.load(open('Mallory.pub'));b['iss_pub']=m;json.dump(b,open('y.badge','w'))"
! ck Sage.key y.badge Sage.pub room.read && pass "swapping in another key as the kin is refused"
AID=$(python3 -c "import json;print(json.load(open('a.badge'))['id'])"); $B revoke trust.ledger Hunter.key "$AID" trust.anchor >/dev/null
! ck Sage.key s.badge Sage.pub room.read && pass "revoking the kin's badge retires their companion too"
[ "$N" -eq 9 ] || { echo "FAIL: only $N of 9"; exit 1; }
echo "ALL 9 COMPANION TESTS PASS ∴Ω⧂"
