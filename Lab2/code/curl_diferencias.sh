set -uo pipefail
cd "$(dirname "$0")"

[ -f valido.html ]   || bash ./curl_valido.sh
[ -f invalido.html ] || bash ./curl_invalido.sh

echo
echo "== 1) Tamano de la respuesta (bytes) =="
wc -c valido.html invalido.html

echo
echo "== 2) Codigo HTTP (cabeceras) =="
grep -i '^HTTP/' head_valido.txt head_invalido.txt

echo
echo "== 3) Content-Length declarado =="
grep -i '^Content-Length:' head_valido.txt head_invalido.txt

echo
echo "== 4) Lineas clave (welcome / incorrect / img / protected area) =="
grep -iE 'welcome|incorrect|<img|protected area' valido.html invalido.html || true

echo
echo "== 5) diff crudo (valido vs invalido) =="
diff valido.html invalido.html || true
