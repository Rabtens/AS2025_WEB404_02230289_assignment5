#!/usr/bin/env bash
#
# test_waf.sh - Send normal and malicious requests and check the WAF's reaction.
#
# Usage:  sudo ./test_waf.sh       (sudo only needed to list the rules that fired)
#         SITE_PORT=8081 ./test_waf.sh   (optional: force a port; normally detected automatically)
#
# The script reads /etc/modsecurity/modsecurity.conf to learn the mode:
#   DetectionOnly -> every request should return 200 (attacks are only logged)
#   On            -> attacks should return 403 (blocked), normal requests 200
#
# The port is read from the virtual host that setup_waf.sh created (it may not be 8080 if 8080 was busy).
if [ -z "${SITE_PORT:-}" ]; then
  SITE_PORT="$(awk '/^Listen/{print $2; exit}' /etc/apache2/sites-available/waf-lab.conf 2>/dev/null)"
fi
SITE_PORT="${SITE_PORT:-8080}"
BASE="http://localhost:${SITE_PORT}"
MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
ERR_LOG="/var/log/apache2/waf-lab-error.log"

MODE="$(grep -E '^SecRuleEngine' "$MODSEC_CONF" 2>/dev/null | awk '{print $2}')"
MODE="${MODE:-unknown}"

if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null)" != "200" ]; then
  echo "ERROR: $BASE is not reachable. Did you run 'sudo ./setup_waf.sh' first?"
  exit 1
fi

# remember how long the error log is so we only report rules fired during this run
START_LINES=0
[ -r "$ERR_LOG" ] && START_LINES="$(wc -l < "$ERR_LOG")"

PASS=0; FAIL=0

echo "=============================================================="
echo " WAF test run   |  SecRuleEngine = $MODE  |  target = $BASE"
echo "=============================================================="
printf '%-34s %-9s %-9s %s\n' "TEST" "EXPECTED" "GOT" "RESULT"
printf '%-34s %-9s %-9s %s\n' "----" "--------" "---" "------"

# run_test <name> <benign|attack> <curl args...>
run_test() {
  local name="$1" kind="$2"; shift 2
  local code expected result
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@")"

  if [ "$kind" = "benign" ]; then
    expected=200
  elif [ "$MODE" = "On" ]; then
    expected=403
  else
    expected=200
  fi

  if [ "$code" = "$expected" ]; then result="PASS"; PASS=$((PASS+1)); else result="FAIL"; FAIL=$((FAIL+1)); fi
  printf '%-34s %-9s %-9s %s\n' "$name" "$expected" "$code" "$result"
}

# ---------- normal traffic (must never be blocked) ----------
run_test "Normal: home page"            benign "$BASE/"
run_test "Normal: search 'hello world'" benign -G --data-urlencode "q=hello world" "$BASE/search.php"
run_test "Normal: login form post"      benign -d "username=alice&password=Secret123" "$BASE/login.php"

# ---------- attacks ----------
run_test "SQLi: ' OR '1'='1"            attack -G --data-urlencode "q=' OR '1'='1" "$BASE/search.php"
run_test "SQLi: UNION SELECT"           attack -G --data-urlencode "q=1 UNION SELECT username,password FROM users--" "$BASE/search.php"
run_test "SQLi in POST body"            attack --data-urlencode "username=admin' OR 1=1--" -d "password=x" "$BASE/login.php"
run_test "XSS: <script> tag"            attack -G --data-urlencode "q=<script>alert(1)</script>" "$BASE/search.php"
run_test "XSS: img onerror"             attack -G --data-urlencode "q=<img src=x onerror=alert(1)>" "$BASE/search.php"
run_test "Path traversal: ../etc/passwd" attack -G --data-urlencode "page=../../../../etc/passwd" "$BASE/view.php"
run_test "Command injection: ;cat"      attack -G --data-urlencode "host=127.0.0.1; cat /etc/passwd" "$BASE/ping.php"
run_test "Scanner user-agent (sqlmap)"  attack -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "$BASE/"
run_test "Custom rule: debug=true"      attack "$BASE/search.php?debug=true"
run_test "Custom rule: /admin"          attack "$BASE/admin/"

echo "--------------------------------------------------------------"
echo " Passed: $PASS    Failed: $FAIL"
echo "--------------------------------------------------------------"

# ---------- show which rules fired ----------
if [ -r "$ERR_LOG" ]; then
  echo
  echo "Rules that fired during this run (hits  rule-id  message):"
  tail -n +"$((START_LINES+1))" "$ERR_LOG" \
    | grep -o '\[id "[0-9]*"\].*\[msg "[^"]*"\]' \
    | sed -E 's/\[id "([0-9]+)"\].*\[msg "([^"]*)"\]/\1|\2/' \
    | grep -v -E '^(949110|980130)\|' \
    | sort | uniq -c | sort -rn | head -25 \
    | awk '{n=$1; $1=""; split($0,a,"|"); gsub(/^ +/,"",a[1]); printf "%5s  %-8s %s\n", n, a[1], substr(a[2],1,70)}'
  echo
  echo "(Rules 949110/980130 are the anomaly-score totals; they decide the block and are hidden above.)"
else
  echo
  echo "(Run with sudo to also list the rule IDs from $ERR_LOG)"
fi

[ "$FAIL" -eq 0 ]