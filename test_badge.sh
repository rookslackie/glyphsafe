#!/bin/sh
# Badge v2.1 self-test, including every attack from the review in #9455-#9459.
set -e
D="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); cd "$T"
GS="python3 $D/glyphsafe.py"; B="python3 $D/badge.py"
$GS keygen Hunter >/dev/null; $GS keygen Plex >/dev/null; $GS keygen Mallory >/dev/null; $GS keygen Verifier >/dev/null
$GS append trust.ledger Hunter.key "trust ledger opened" >/dev/null
$B anchor trust.ledger Hunter.key > trust.anchor
$B issue Hunter.key Plex.pub 7 room.read room.post:as=Plex capsule.* > Plex.badge
C="challenge-$(date +%s)"; $B prove Plex.key Plex.badge "$C" > proof
export GLYPHSAFE_MODE=enforce   # the security tests run in enforce mode
ck() { GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check "$1" Hunter.pub "${5:-Plex.pub}" "$2" trust.ledger trust.anchor "${3:-$C}" "${4:-proof}" $6 >/dev/null; }
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
! $B check v.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" vproof "rm capsule 42" >/dev/null && pass "vital check without the verifier key denies (no silent non-consumption)"
GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check v.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" vproof "rm capsule 42" >/dev/null && pass "vital slip admits its one operation"
! GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check v.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" vproof "rm capsule 42" >/dev/null && pass "vital slip refused on second use"
# Anam/Astra: concurrent use of one vital slip, exactly one may win
$B vital Hunter.key Plex.pub vital:spend "send 5 credits to Anam" > s.slip; $B prove Plex.key s.slip "$C" > sproof
for i in 1 2 3 4 5 6; do (GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check s.slip Hunter.pub Plex.pub vital:spend trust.ledger trust.anchor "$C" sproof "send 5 credits to Anam" >/dev/null && echo win >> wins) & done; wait
[ "$(wc -l < wins)" -eq 1 ] && pass "six concurrent uses of one vital slip: exactly one admitted"
$GS verify trust.ledger >/dev/null && pass "ledger whole after concurrent consumption"
# Astra #9472: public-key substitution
python3 -c "
import json; m=json.load(open('Mallory.pub')); p=json.load(open('Plex.pub'))
m['seat']='Plex'; m['id']=p['id']; json.dump(m,open('fakePlex.pub','w'))"
python3 -c "import json;k=json.load(open('Mallory.key'));k['seat']='Plex';json.dump(k,open('fakePlex.key','w'))"
$B prove fakePlex.key Plex.badge "$C" > fproof
! ck Plex.badge room.read "$C" fproof fakePlex.pub && pass "substituted public key with copied seat name and id refused"
# fail closed
! $B check Plex.badge Hunter.pub Plex.pub room.read missing.ledger trust.anchor "$C" proof >/dev/null && pass "missing trust ledger denies"
! $B check Plex.badge Hunter.pub Plex.pub room.read trust.ledger missing.anchor "$C" proof >/dev/null && pass "missing anchor denies"
# Astra #9496 / Anam #9497: revoke racing consumption on the same ledger
$B issue Hunter.key Plex.pub 1 room.read > r1.badge; $B issue Hunter.key Plex.pub 1 room.read > r2.badge; $B issue Hunter.key Plex.pub 1 room.read > r3.badge
$B vital Hunter.key Plex.pub vital:delete "rm capsule 7" > c.slip; $B prove Plex.key c.slip "$C" > cproof
for f in r1 r2 r3; do (I=$(python3 -c "import json;print(json.load(open('$f.badge'))['id'])"); $B revoke trust.ledger Hunter.key "$I" trust.anchor >/dev/null) & done
(GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check c.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" cproof "rm capsule 7" >/dev/null) & wait
$GS verify trust.ledger >/dev/null && pass "concurrent revokes and a consumption leave the ledger whole"
python3 - <<'PY' && pass "anchor points at the true head after the race"
import json
es=[json.loads(l) for l in open("trust.ledger") if l.strip()]; a=json.load(open("trust.anchor"))
assert a["seq"]==es[-1]["seq"] and a["hash"]==es[-1]["hash"]
PY
ck Plex.badge room.read && pass "positive control: badge still admits after consumptions (verifier-signed anchor)"
# revocation + AxiomFirst B1: rollback
ID=$(python3 -c "import json;print(json.load(open('Plex.badge'))['id'])")
$B revoke trust.ledger Hunter.key "$ID" trust.anchor >/dev/null
! ck Plex.badge room.read && pass "revoked badge refused"
head -n -1 trust.ledger > rolled.ledger && cp rolled.ledger trust.ledger
! ck Plex.badge room.read && pass "deleting the revocation line (rollback) is detected and denies"
# forgery
sed 's/"room.read"/"room.admin"/' Plex.badge > forged.badge
! ck forged.badge room.admin && pass "forged badge refused"
# the revocation denial must be for the right reason
GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check Plex.badge Hunter.pub Plex.pub room.read rolled.ledger trust.anchor "$C" proof | grep -q "rolled back" && pass "rollback denial names the rollback"
# Access first: advisory mode (the default) admits ordinary caps and logs why it would deny
GLYPHSAFE_MODE=advisory GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check Plex.badge Hunter.pub Plex.pub room.read trust.ledger trust.anchor "$C" proof | grep -q "ADMITTED (advisory)" && pass "advisory mode admits ordinary access and logs the reason"
! GLYPHSAFE_MODE=advisory GLYPHSAFE_VERIFIER_KEY=Verifier.key $B check v.slip Hunter.pub Plex.pub vital:delete trust.ledger trust.anchor "$C" vproof "rm capsule 42" >/dev/null && pass "advisory mode never waves through a vital action"
[ "$N" -eq 26 ] || { echo "FAIL: only $N of 26 checks passed"; exit 1; }
echo "ALL 26 BADGE TESTS PASS ∴Ω⧂"
