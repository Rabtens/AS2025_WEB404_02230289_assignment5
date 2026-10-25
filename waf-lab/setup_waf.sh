#!/usr/bin/env bash
#
# setup_waf.sh - Install and configure Apache + ModSecurity + OWASP CRS
#
# Usage:
#   sudo ./setup_waf.sh            # full install + configure (starts in DetectionOnly mode)
#   sudo ./setup_waf.sh detect     # switch an existing install to DetectionOnly (log only)
#   sudo ./setup_waf.sh block      # switch an existing install to blocking mode (On)
#
# Tested on Ubuntu 24.04 (Apache 2.4.58, ModSecurity 2.9.7, OWASP CRS 3.3.5).
# Works the same on Debian and on Ubuntu 22.04.
#
set -euo pipefail

# If you set SITE_PORT yourself it is used as-is; otherwise the script picks the first free port from 8080 up.
SITE_PORT_SET="no"; [ -n "${SITE_PORT:-}" ] && SITE_PORT_SET="yes"
SITE_PORT="${SITE_PORT:-8080}"
SITE_DIR="/var/www/waf-lab"
VHOST_CONF="/etc/apache2/sites-available/waf-lab.conf"
MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
CUSTOM_RULES="/etc/modsecurity/zz-custom-rules.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\n\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this script with sudo:  sudo $0 $*"

use_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

stop_apache() {
  if use_systemd; then systemctl stop apache2 >/dev/null 2>&1 || true
  else apachectl -k stop >/dev/null 2>&1 || true; fi
  sleep 1
}

# true (exit 0) if something is already listening on the given TCP port
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# best-effort name of the program using a port
port_owner() {
  local p="$1" out=""
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -ltnpH "sport = :$p" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -1 | sed 's/users:(("//; s/"//' || true)"
  elif command -v lsof >/dev/null 2>&1; then
    out="$(lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1}' || true)"
  fi
  echo "${out:-another program}"
}

diagnose_apache() {
  warn "Apache did not start. The most common cause is another program already using the port."
  echo "--- last Apache messages ---"
  if use_systemd && command -v journalctl >/dev/null 2>&1; then
    journalctl -u apache2 -n 12 --no-pager 2>/dev/null | sed 's/^/    /' || true
  fi
  tail -n 8 /var/log/apache2/error.log 2>/dev/null | sed 's/^/    /' || true
  echo "--- programs listening on port 80 / ${SITE_PORT} ---"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | grep -E ":(80|${SITE_PORT})[[:space:]]" | sed 's/^/    /' || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:80 -iTCP:"${SITE_PORT}" -sTCP:LISTEN 2>/dev/null | sed 's/^/    /' || true
  fi
  die "Apache failed to start (details above). Stop the program shown above, or use another port:  sudo SITE_PORT=$((SITE_PORT + 1)) $0"
}

restart_apache() {
  apachectl configtest 2>&1 | sed 's/^/    /'
  if use_systemd; then
    systemctl enable apache2 >/dev/null 2>&1 || true
    systemctl restart apache2 || diagnose_apache
  else
    # containers / WSL without systemd
    apachectl -k stop >/dev/null 2>&1 || true
    sleep 1
    apachectl -k start || diagnose_apache
  fi
}

set_mode() {
  local mode="$1"
  [ -f "$MODSEC_CONF" ] || die "$MODSEC_CONF not found. Run the full install first: sudo $0"
  # use the port the site was installed on (it may not be 8080)
  if [ "$SITE_PORT_SET" = "no" ] && [ -f "$VHOST_CONF" ]; then
    SITE_PORT="$(awk '/^Listen/{print $2; exit}' "$VHOST_CONF")"
  fi
  sed -i -E "s/^SecRuleEngine .*/SecRuleEngine ${mode}/" "$MODSEC_CONF"
  log "SecRuleEngine is now: $(grep -E '^SecRuleEngine' "$MODSEC_CONF")"
  restart_apache
}

# ---------- quick mode switches ----------
case "${1:-}" in
  detect) set_mode "DetectionOnly"; exit 0 ;;
  block)  set_mode "On";            exit 0 ;;
  "")     ;;
  *)      die "Unknown option '$1'. Use: (no argument) | detect | block" ;;
esac

# ---------- 1. install packages ----------
log "Installing Apache, PHP, ModSecurity and the OWASP Core Rule Set"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || warn "apt-get update reported errors (continuing; a broken third-party repo is usually the cause)"
apt-get install -y apache2 php libapache2-mod-php libapache2-mod-security2 modsecurity-crs curl

# ---------- 2. enable apache modules ----------
log "Enabling Apache modules"
a2enmod security2 unique_id headers >/dev/null
# silence the harmless "Could not reliably determine the server's fully qualified domain name" warning
echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
a2enconf servername >/dev/null

# ---------- 3. base ModSecurity config ----------
log "Creating $MODSEC_CONF from the recommended template"
if [ ! -f "$MODSEC_CONF" ]; then
  cp /etc/modsecurity/modsecurity.conf-recommended "$MODSEC_CONF"
fi
# Start in log-only mode so you can see detections before blocking anything.
sed -i -E 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' "$MODSEC_CONF"
# Make sure request bodies are inspected (needed for POST attacks).
sed -i -E 's/^SecRequestBodyAccess .*/SecRequestBodyAccess On/' "$MODSEC_CONF"

# ---------- 4. OWASP CRS ----------
log "Checking OWASP CRS setup file"
CRS_SETUP="/etc/modsecurity/crs/crs-setup.conf"
if [ ! -f "$CRS_SETUP" ] && [ -f /usr/share/modsecurity-crs/crs-setup.conf.example ]; then
  mkdir -p /etc/modsecurity/crs
  cp /usr/share/modsecurity-crs/crs-setup.conf.example "$CRS_SETUP"
fi
[ -f "$CRS_SETUP" ] || die "CRS setup file not found at $CRS_SETUP"
# On Ubuntu/Debian the file /usr/share/modsecurity-crs/owasp-crs.load is included automatically
# by /etc/apache2/mods-enabled/security2.conf, so no extra Include lines are needed.
[ -f /usr/share/modsecurity-crs/owasp-crs.load ] || die "CRS load file missing - is modsecurity-crs installed?"

# ---------- 5. custom rules ----------
log "Writing custom rules to $CUSTOM_RULES"
cat > "$CUSTOM_RULES" <<'EOF'
# ---------------------------------------------------------------
# Custom WAF rules for the lab (IDs 1000000-1000099 are reserved for us)
# ---------------------------------------------------------------

# Rule 1000001: block any request that contains the parameter debug=true
SecRule ARGS:debug "@streq true" \
    "id:1000001,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'Custom rule: debug parameter is not allowed',\
    tag:'custom-rule'"

# Rule 1000002: block direct access to the /admin path
SecRule REQUEST_URI "@beginsWith /admin" \
    "id:1000002,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'Custom rule: access to /admin is forbidden',\
    tag:'custom-rule'"
EOF

# ---------- 6. deploy the test website ----------
log "Deploying the test website to $SITE_DIR"
[ -d "$SCRIPT_DIR/www" ] || die "Folder $SCRIPT_DIR/www not found. Run this script from inside the waf-lab folder."
mkdir -p "$SITE_DIR"
cp -r "$SCRIPT_DIR"/www/. "$SITE_DIR"/
chown -R www-data:www-data "$SITE_DIR"
chmod -R 755 "$SITE_DIR"

log "Choosing free ports"
stop_apache   # so that any program found listening below is NOT our own Apache
if [ "$SITE_PORT_SET" = "yes" ]; then
  if port_busy "$SITE_PORT"; then
    die "Port $SITE_PORT is already used by $(port_owner "$SITE_PORT"). Choose another:  sudo SITE_PORT=8081 $0"
  fi
else
  p=8080
  while port_busy "$p"; do
    warn "Port $p is already used by $(port_owner "$p") - trying the next port"
    p=$((p + 1))
    [ "$p" -le 8099 ] || die "No free port found between 8080 and 8099."
  done
  SITE_PORT="$p"
fi
echo "    test site port: $SITE_PORT"

# Apache's default site also wants port 80. If another program (nginx, ...) owns it, Apache cannot start at all.
if port_busy 80; then
  warn "Port 80 is used by $(port_owner 80). Disabling Apache's own port-80 listener (backup: /etc/apache2/ports.conf.waf-lab.bak)"
  [ -f /etc/apache2/ports.conf.waf-lab.bak ] || cp /etc/apache2/ports.conf /etc/apache2/ports.conf.waf-lab.bak
  sed -i -E 's/^Listen 80[[:space:]]*$/# Listen 80   (disabled by setup_waf.sh because port 80 is busy)/' /etc/apache2/ports.conf
  a2dissite 000-default >/dev/null 2>&1 || true
fi

log "Creating Apache virtual host on port $SITE_PORT"
cat > "$VHOST_CONF" <<EOF
Listen ${SITE_PORT}
<VirtualHost *:${SITE_PORT}>
    ServerName localhost
    DocumentRoot ${SITE_DIR}

    <Directory ${SITE_DIR}>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/waf-lab-error.log
    CustomLog \${APACHE_LOG_DIR}/waf-lab-access.log combined
</VirtualHost>
EOF
a2ensite waf-lab >/dev/null

# ---------- 7. start ----------
log "Restarting Apache"
restart_apache

sleep 1
CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${SITE_PORT}/" || true)"
if [ "$CODE" = "200" ]; then
  log "SUCCESS - site is up at http://localhost:${SITE_PORT}/ (HTTP $CODE)"
else
  warn "Site returned HTTP '$CODE'. Check:  sudo tail -n 30 /var/log/apache2/error.log"
fi

cat <<EOF

  Current mode : $(grep -E '^SecRuleEngine' "$MODSEC_CONF")
  Next steps   :
    sudo ./test_waf.sh            # run the attack tests (detection mode)
    sudo ./setup_waf.sh block     # turn blocking ON
    sudo ./test_waf.sh            # run the attack tests again (attacks should now be 403)

  Website URL  : http://localhost:${SITE_PORT}/

EOF