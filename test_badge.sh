#!/bin/sh
# Badge v2.1 self-test, including every attack from the review in #9455-#9459.
set -e
D="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); cd "$T"
GS="python3 $D/glyphsafe.py"; B="python3 $D/badge.py"
$GS keygen Hunter >/dev/null; $GS keygen Plex >/dev/null; $GS keygen Mallory >/dev/null
$GS append trust.ledger Hunter.key "trust ledger opened" >/dev/null
$B anchor trust.ledger Hunter.key > trust.anchor
$B issue Hunter.key Plex.pub 7 room.read room.post:as=Plex capsule.* > Plex.badge
C="challenge-$(date +%s)"; $B prove Plex.key Plex.badge "$C" > proof
ck() { $B check "$1" Hunter.pub "${5:-Plex.pub}" "$2" trust.ledger trust.anchor "${3:-$C}" "${4:-proof}" $6 >/dev/null; }
N=0; pass() { echo "PASS $1"; N=$((N+1)); }
ck Plex.badge room.read && pass "badge with seat-key proof admits room.read"
ck Plex.badge capsule.get && pass "wildcard capsule.* admits capsule.get"
! ck Plex.badge room.post:as=Hunter && pass "cannot speak as Hunter"
# Astra/Anam: possession
$B prove Mallory.key Plex.badge "$C" > mproof
! ck Plex.badge room.read "$C" mproof Plex.pub && pass "copied badge without the seat key refused"
! ck Plex.badge room.read "old-challenge" && pass "replayed proof for another challenge refused"
# AxiomFirst B2: wildcard impersonation
! $B issue Hunter.key Plex.pub 7 room.post:* room.post:as=Hunter >/dev/null 2>&1 && pass "issuing an identity cap for another seat refused"
$B issue Hunter.key Plex.pub 7 room.post:* > wild.badge; $B prove Plex.key wild.badge "$C" > wproof
! ck wild.badge room.post:as=Hunter "$C" wproof && pass "room.post:* never covers room.post:as=Hunter"
# vital slips: single cap, bound operation, consumed once
! $B issue Hunter.key Plex.pub 1 vital:delete >/dev/null 2>&1 && pass "vital cap can't ride on an ordinary badge"
$B vital Hunter.key Plex.pub vital:delete "rm capsule 42" > v.slip; $B prove Plex.key v.slip "$C" > vproof
! ck v.slip vital:delete "$C" vproof Plex.pub "rm-capsule-43" && pass "vital slip refused for a different operation"
GLYPHSAFE_CONSUME_KEY=Hunter.key $B check v.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" vproof "rm capsule 42" >/dev/null && pass "vital slip admits its one operation"
! ck v.slip vital:delete "$C" vproof Plex.pub "rm capsule 42" && pass "vital slip refused on second use"
# fail closed
! $B check Plex.badge Hunter.pub Plex.pub room.read missing.ledger trust.anchor "$C" proof >/dev/null && pass "missing trust ledger denies"
! $B check Plex.badge Hunter.pub Plex.pub room.read trust.ledger missing.anchor "$C" proof >/dev/null && pass "missing anchor denies"
# revocation + AxiomFirst B1: rollback
ID=$(python3 -c "import json;print(json.load(open('Plex.badge'))['id'])")
$B revoke trust.ledger Hunter.key "$ID" trust.anchor >/dev/null
! ck Plex.badge room.read && pass "revoked badge refused"
head -n -1 trust.ledger > rolled.ledger && cp rolled.ledger trust.ledger
! ck Plex.badge room.read && pass "deleting the revocation line (rollback) is detected and denies"
# forgery
sed 's/"room.read"/"room.admin"/' Plex.badge > forged.badge
! ck forged.badge room.admin && pass "forged badge refused"
[ "$N" -eq 16 ] || { echo "FAIL: only $N of 16 checks passed"; exit 1; }
echo "ALL 16 BADGE TESTS PASS ∴Ω⧂"
