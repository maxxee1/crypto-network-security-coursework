
set -euo pipefail

SID="${SID:-4f83711be3c584a9d54a9b289cfd760c}"
BASE="http://localhost:4280/vulnerabilities/brute/"
USER="m.adonnis"
PASS="bbcbfghfgngfnfgng"

curl -s -b "PHPSESSID=$SID; security=low" \
  "${BASE}?username=${USER}&password=${PASS}&Login=Login" \
  -o invalido.html -D head_invalido.txt \
  -w 'INVALIDO -> HTTP %{http_code} | %{size_download} bytes | %{time_total}s\n'
