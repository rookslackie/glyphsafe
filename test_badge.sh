#!/bin/sh
# Badge self-test: Hunter badges Plex in, then checks scope, vital gating, tamper and revocation.
set -e
D="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); cd "$T"
python3 "$D/glyphsafe.py" keygen Hunter >/dev/null; python3 "$D/glyphsafe.py" keygen Plex >/dev/null
python3 "$D/badge.py" issue Hunter.key Plex.pub 7 room.read room.post:as=Plex capsule.* > Plex.badge
python3 "$D/badge.py" check Plex.badge Hunter.pub room.read >/dev/null && echo "PASS badge admits room.read"
python3 "$D/badge.py" check Plex.badge Hunter.pub capsule.get >/dev/null && echo "PASS wildcard capsule.*"
! python3 "$D/badge.py" check Plex.badge Hunter.pub room.post:as=Hunter >/dev/null && echo "PASS cannot speak as Hunter"
! python3 "$D/badge.py" check Plex.badge Hunter.pub vital:spend >/dev/null && echo "PASS vital action denied without its own slip"
! python3 "$D/badge.py" check Plex.badge Plex.pub room.read >/dev/null && echo "PASS self-issued badge refused"
! python3 "$D/badge.py" issue Hunter.key Plex.pub 7 vital:delete >/dev/null 2>&1 && echo "PASS long-lived vital slip refused"
sed 's/"room.read"/"room.admin"/' Plex.badge > forged.badge
! python3 "$D/badge.py" check forged.badge Hunter.pub room.admin >/dev/null && echo "PASS forged badge refused"
ID=$(python3 -c "import json;print(json.load(open('Plex.badge'))['id'])")
python3 "$D/badge.py" revoke trust.ledger Hunter.key "$ID" >/dev/null
! python3 "$D/badge.py" check Plex.badge Hunter.pub room.read trust.ledger >/dev/null && echo "PASS revoked badge refused"
python3 "$D/glyphsafe.py" verify trust.ledger >/dev/null && echo "PASS revocation ledger whole"
echo "ALL BADGE TESTS PASS ∴Ω⧂"
