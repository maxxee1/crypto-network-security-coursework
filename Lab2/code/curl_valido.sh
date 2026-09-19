set -euo pipefail

SID="${SID:-4f83711be3c584a9d54a9b289cfd760c}"
BASE="http://localhost:4280/vulnerabilities/brute/"
USER="pablo"
PASS="letmein"

curl -s -b "PHPSESSID=$SID; security=low" \
  "${BASE}?username=${USER}&password=${PASS}&Login=Login" \
  -o valido.html -D head_valido.txt \
  -w 'VALIDO   -> HTTP %{http_code} | %{size_download} bytes | %{time_total}s\n'
