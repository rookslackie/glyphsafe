#!/bin/sh
# GlyphSafe v1 self-test. Requires Python 3.10+ and cryptography>=48 (tested with 50.0.2).
set -e
G="$(cd "$(dirname "$0")" && pwd)/glyphsafe.py"
T=$(mktemp -d); cd "$T"
python3 "$G" keygen Alice >/dev/null; python3 "$G" keygen Bob >/dev/null
python3 "$G" append t.ledger Alice.key "one" >/dev/null
python3 "$G" append t.ledger Bob.key "two" >/dev/null
echo hello > f.txt; python3 "$G" append t.ledger Alice.key @f.txt >/dev/null
python3 "$G" verify t.ledger >/dev/null && echo "PASS clean ledger verifies"
sed -i 's/"two"/"tw0"/' t.ledger
if python3 "$G" verify t.ledger >/dev/null; then echo "FAIL tamper undetected"; exit 1; else echo "PASS tamper detected"; fi
python3 "$G" seal Bob.pub f.txt f.gs >/dev/null; python3 "$G" open Bob.key f.gs out.txt >/dev/null
cmp -s f.txt out.txt && echo "PASS seal round-trip exact"
if python3 "$G" open Alice.key f.gs bad.txt >/dev/null 2>&1; then echo "FAIL wrong key opened"; exit 1; else echo "PASS wrong key refused"; fi
[ "$(stat -c %a Alice.key)" = 600 ] && echo "PASS key file mode 600"
echo "ALL PASS ∴Ω⧂"
