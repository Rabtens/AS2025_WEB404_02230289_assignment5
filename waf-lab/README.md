# Configuring and Testing a Web Application Firewall (WAF) with ModSecurity and the OWASP Core Rule Set

**Assignment Task 4:** Configure and test a Web Application Firewall (WAF) to protect against common server-side attacks.

---

## Abstract

This report documents the installation, configuration and testing of a Web Application Firewall built from **Apache 2.4**, **ModSecurity v2** and the **OWASP Core Rule Set (CRS)**. A small PHP test website was deployed behind the WAF and attacked with SQL injection, cross-site scripting (XSS), path traversal, command injection and a scanner user-agent. The WAF was first run in **DetectionOnly** mode, where attacks were logged but allowed through, and was then switched to **blocking** mode, where every attack was rejected with `403 Forbidden` while normal traffic continued to receive `200 OK`. Two custom rules were also written, and the log files were examined. In total, 13 automated tests were run in each mode and all 13 produced the expected result in both.

---

## 1. Introduction

### 1.1 What is a WAF?

A Web Application Firewall sits in front of a web application and inspects every HTTP request. If a request looks like an attack, the WAF logs it and, in blocking mode, rejects it before it reaches the application.

```
 Attacker / Browser ──HTTP──▶ [ Apache + ModSecurity WAF + OWASP CRS ] ──▶ PHP test website
                                         │
                                         ├── clean request   → 200 OK, passed through
                                         └── attack detected → logged, then 403 Forbidden (blocking mode)
```

### 1.2 Components used

| Component | Role |
|---|---|
| **Apache 2.4** | The web server hosting the test website |
| **ModSecurity v2** (`libapache2-mod-security2`) | The WAF engine |
| **OWASP Core Rule Set (CRS)** (`modsecurity-crs`) | Ready-made rules covering SQL injection, XSS, path traversal, command injection, scanners, etc. |
| **Custom rules** (`zz-custom-rules.conf`) | Two rules written for this lab (block `debug=true`, block `/admin`) |
| **PHP test website** (`www/`) | Simple pages that *echo* input. They never touch a real database, file or shell, so the lab is safe |

### 1.3 How the CRS decides to block (anomaly scoring)

Each suspicious pattern found in a request adds points to that request's anomaly score (Critical = 5, Error = 4, Warning = 3, Notice = 2). Rule **949110** blocks the request when the inbound score reaches **5**. In *DetectionOnly* mode the score is still calculated and logged, but nothing is blocked.

### 1.4 Attacks covered

| # | Attack | Example payload | CRS rule family |
|---|---|---|---|
| 1 | SQL injection | `' OR '1'='1` | 942xxx |
| 2 | Cross-site scripting (XSS) | `<script>alert(1)</script>` | 941xxx |
| 3 | Path traversal / LFI | `../../../../etc/passwd` | 930xxx |
| 4 | Command injection (RCE) | `127.0.0.1; cat /etc/passwd` | 932xxx |
| 5 | Scanner / bot detection | `User-Agent: sqlmap` | 913xxx |
| 6 | Custom rules | `?debug=true`, `/admin/` | 1000001, 1000002 |

---

## 2. Environment

| Item | Details |
|---|---|
| Operating system | Ubuntu 22.04 / 24.04 Linux (a Debian-based system also works) |
| Versions used | Apache 2.4.58, ModSecurity 2.9.7, OWASP CRS 3.3.5 |
| Access | A user with `sudo` rights and an internet connection (for `apt`) |
| Client | A web browser, plus `curl` in the terminal |

## 3. Project structure

```
waf-lab/
├── README.md          ← this report
├── setup_waf.sh       ← installs & configures everything (also switches detect/block mode)
├── test_waf.sh        ← sends normal + attack requests and shows PASS/FAIL
├── www/               ← the test website (copied to /var/www/waf-lab)
│   ├── index.html
│   ├── search.php     (XSS target)
│   ├── login.php      (SQL injection target)
│   ├── view.php       (path traversal target)
│   ├── ping.php       (command injection target)
│   └── admin/index.html
└── screenshots/       ← figures used in this report
```

---

## 4. Implementation

### 4.1 Preparing the project files

The `waf-lab` folder was copied to the Linux machine and a terminal was opened inside it. The two scripts were made executable:

```bash
cd ~/waf-lab
ls
chmod +x setup_waf.sh test_waf.sh
```

The listing showed `README.md  screenshots  setup_waf.sh  test_waf.sh  www`, confirming that all project files were present.

![alt text](<screenshots/Screenshot from 2026-10-25 22-47-27.png>)

### 4.2 Installing and configuring the WAF

The whole setup was performed with one command:

```bash
sudo ./setup_waf.sh
```

The script carried out the following steps:

1. Installed `apache2`, `php`, `libapache2-mod-security2`, `modsecurity-crs` and `curl`.
2. Enabled the Apache modules `security2`, `unique_id` and `headers`.
3. Created `/etc/modsecurity/modsecurity.conf` from the recommended template and set **`SecRuleEngine DetectionOnly`**, so that attacks would be logged but not yet blocked.
4. Confirmed that the OWASP CRS was loaded. Ubuntu loads it automatically through `/usr/share/modsecurity-crs/owasp-crs.load`.
5. Wrote two custom rules to `/etc/modsecurity/zz-custom-rules.conf`.
6. Deployed the test site to `/var/www/waf-lab` and created an Apache virtual host on **port 8080**.
7. Restarted Apache and checked that the site returned HTTP 200.

The script finished with the following lines, showing that the site was running and the WAF was in log-only mode:

```
[+] SUCCESS - site is up at http://localhost:8080/ (HTTP 200)
  Current mode : SecRuleEngine DetectionOnly
```

![alt text](<screenshots/Screenshot from 2026-10-25 23-08-08.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-08-44.png>)

A warning about an unrelated third-party repository (for example `Failed to fetch https://download.docker.com/...`) can appear during `apt-get update`. It is harmless: the script continues and the Ubuntu packages are still installed.

### 4.3 Verifying that the WAF is loaded

The following commands were used to confirm that the ModSecurity module was active, the configuration was valid, the engine mode was correct and the CRS rule files were present:

```bash
sudo apachectl -M | grep -E "security2|unique_id"
sudo apachectl configtest
grep -E "^SecRuleEngine" /etc/modsecurity/modsecurity.conf
ls /usr/share/modsecurity-crs/rules | head -20
```

The output was:

```
 unique_id_module (shared)
 security2_module (shared)
Syntax OK
SecRuleEngine DetectionOnly
REQUEST-901-INITIALIZATION.conf ... REQUEST-941-APPLICATION-ATTACK-XSS.conf, REQUEST-942-APPLICATION-ATTACK-SQLI.conf ...
```

Both modules were loaded, the Apache configuration passed its syntax check, and the CRS files for SQL injection, XSS and the other attack families were in place.

![alt text](<screenshots/Screenshot from 2026-10-25 23-13-43.png>)

### 4.4 The test website

The test website was opened in a browser at **http://localhost:8081/**. (When the browser runs on the host machine of a VM, `http://<VM-IP>:8081/` is used instead; the IP address is shown by `hostname -I`.) The home page links to four pages, each acting as a target for one attack type.

![alt text](<screenshots/Screenshot from 2026-10-25 23-08-44.png>)

---

## 5. Testing in DetectionOnly mode

In this mode ModSecurity analyses every request and writes detections to its log, but it does not block anything.

### 5.1 Automated test

The test script sends 3 normal requests and 10 attack requests and compares each HTTP status code with the expected one:

```bash
sudo ./test_waf.sh
```

(`sudo` lets the script also list the rules that fired, read from the Apache log.)

The header showed `SecRuleEngine = DetectionOnly`. All 13 requests returned `200`, giving **Passed: 13, Failed: 0**. This is the expected result for this mode: the attacks were not blocked. The list of fired rules below the table showed that they had nevertheless been detected, for example:

| Rule ID | Detection |
|---|---|
| 942100, 942190, 942270, 942360 | SQL injection |
| 941100, 941110, 941120, 941160 | Cross-site scripting |
| 930100, 930110, 930120 | Path traversal / OS file access |
| 932100, 932160 | Remote command execution |
| 913100 | Security scanner user-agent |
| 1000001, 1000002 | The two custom rules |

![alt text](<screenshots/Screenshot from 2026-10-25 23-15-53.png>)

**Observation:** The attacks returned 200 because the WAF was only logging. The CRS rules still recognised each attack category, which shows that detection works independently of blocking.

### 5.2 Manual attacks in the browser (before blocking)

The following URLs were opened in the browser. Because nothing was blocked, each attack reached the application:

| Attack | URL used |
|---|---|
| XSS | `http://localhost:8081/search.php?q=<script>alert('XSS')</script>` |
| SQL injection | `http://localhost:8081/login.php` → username: `' OR '1'='1` , password: `x` |
| Path traversal | `http://localhost:8081/view.php?page=../../../../etc/passwd` |
| Command injection | `http://localhost:8081/ping.php?host=127.0.0.1;cat /etc/passwd` |

The XSS URL made a JavaScript **alert box** appear. This proves that the attack worked when no blocking was active.

![alt text](<screenshots/Screenshot from 2026-10-25 23-26-41.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-28-26.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-29-44.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-30-07.png>)

### 5.3 Reading the WAF log

The detections were read from the Apache error log of the virtual host:

```bash
sudo grep ModSecurity /var/log/apache2/waf-lab-error.log | tail -n 5
```

Each line is one detection. The entries contained the rule id (for example `[id "941100"]`), the message (`[msg "XSS Attack Detected via libinjection"]`), the severity (`[severity "CRITICAL"]`) and the exact text that matched (`[data "Matched Data: ..."]`).

![alt text](<screenshots/Screenshot from 2026-10-25 23-31-16.png>)

---

## 6. Testing in blocking mode

### 6.1 Enabling blocking and re-running the tests

The WAF was switched from log-only to blocking mode, the setting was checked, and the automated test was run again:

```bash
sudo ./setup_waf.sh block
grep -E "^SecRuleEngine" /etc/modsecurity/modsecurity.conf
sudo ./test_waf.sh
```

The setting changed to `SecRuleEngine On`, and the test header showed `SecRuleEngine = On`. The three normal requests still returned `200`, while **all 10 attack requests returned `403`**, giving **Passed: 13, Failed: 0**.

![alt text](<screenshots/Screenshot from 2026-10-25 23-32-10.png>)

**Observation:** The only change between the two runs was the `SecRuleEngine` setting, yet every attack that had returned 200 now returned 403. Normal requests kept passing because they never collected enough anomaly points to reach the blocking threshold of 5. This is the aim of a WAF: stopping attacks without disturbing legitimate users.

### 6.2 Manual attacks in the browser (after blocking)

The URLs from section 5.2 were opened again. Each of them now showed **403 Forbidden**, and the XSS alert box no longer appeared.

![alt text](<screenshots/Screenshot from 2026-10-25 23-26-41.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-28-26.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-29-44.png>)

![alt text](<screenshots/Screenshot from 2026-10-25 23-30-07.png>)



### 6.3 Confirming the status codes with curl

The raw HTTP responses were checked from the command line:

```bash
curl -i -G --data-urlencode "q=<script>alert(1)</script>" http://localhost:8080/search.php | head -8
curl -i "http://localhost:8080/search.php?q=hello" | head -3
```

The first command returned `HTTP/1.1 403 Forbidden` and the second returned `HTTP/1.1 200 OK`, confirming that only the malicious request was refused.

![alt text](<screenshots/Screenshot from 2026-10-25 23-34-26.png>)

---

## 7. Custom rules and log analysis

### 7.1 Custom rules

Besides the CRS, two rules were written in `/etc/modsecurity/zz-custom-rules.conf`:

```bash
cat /etc/modsecurity/zz-custom-rules.conf
```

| Rule ID | What it does | How it works |
|---|---|---|
| `1000001` | Blocks any request with `debug=true` | `SecRule ARGS:debug "@streq true"` → `deny,status:403` |
| `1000002` | Blocks anything under `/admin` | `SecRule REQUEST_URI "@beginsWith /admin"` → `deny,status:403` |

Both rules worked as intended: `http://localhost:8080/search.php?debug=true` and `http://localhost:8080/admin/` returned **403**, whereas `http://localhost:8080/search.php?q=hello` returned **200**. The file is named `zz-custom-rules.conf` so that it is loaded after the main ModSecurity configuration.

![alt text](<screenshots/Screenshot from 2026-10-25 23-35-14.png>)

### 7.2 Audit log

ModSecurity also keeps a full record of each blocked request (headers, matched rules and so on):

```bash
sudo tail -n 60 /var/log/apache2/modsec_audit.log
```

Each entry is divided into sections: `--A--` (time and client IP), `--B--` (request headers), `--F--` (response) and `--H--` (the matched rules and their messages). The `--H--` section was the most useful, since it lists exactly which rules caused the block.

![alt text](<screenshots/Screenshot from 2026-10-25 23-36-24.png>)

### 7.3 Tuning a false positive (optional)

Real WAFs sometimes block legitimate traffic, which is called a *false positive*. The proper fix is to disable one rule for one URL only, not for the whole site. To demonstrate this, rule `942100` was assumed to wrongly block `/search.php`, and the following rule was appended to `/etc/modsecurity/zz-custom-rules.conf`:

```apache
SecRule REQUEST_URI "@beginsWith /search.php" \
    "id:1000010,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=942100"
```

After reloading Apache, the effect was tested:

```bash
sudo apachectl configtest && sudo apachectl -k graceful
curl -s -o /dev/null -w "%{http_code}\n" -G --data-urlencode "q=' OR '1'='1" http://localhost:8080/search.php   # now 200
curl -s -o /dev/null -w "%{http_code}\n" -G --data-urlencode "q=<script>alert(1)</script>" http://localhost:8080/search.php   # still 403
```

The SQL injection string was now allowed on that page, but the XSS payload was still blocked. This shows that the exclusion was narrow: it removed only one rule on one page. The rule weakens protection, so it was **deleted again** afterwards and Apache was reloaded to restore full protection.

![alt text](<screenshots/Screenshot from 2026-10-25 23-37-30.png>)

---

## 8. Results summary

| Test | Detection mode (expected) | Blocking mode (expected) | Observed |
|---|---|---|---|
| Normal home page / search / login | 200 | 200 | As expected in both modes |
| SQL injection (3 tests) | 200 (logged) | **403** | As expected in both modes |
| XSS (2 tests) | 200 (logged) | **403** | As expected in both modes |
| Path traversal | 200 (logged) | **403** | As expected in both modes |
| Command injection | 200 (logged) | **403** | As expected in both modes |
| Scanner user-agent (sqlmap) | 200 (logged) | **403** | As expected in both modes |
| Custom rule `debug=true` | 200 (logged) | **403** | As expected in both modes |
| Custom rule `/admin/` | 200 (logged) | **403** | As expected in both modes |

All 13 tests passed in DetectionOnly mode and all 13 passed in blocking mode.

---

## 9. Conclusion

A WAF inspects HTTP requests and stops attacks before they reach the web application. In this lab, ModSecurity together with the OWASP Core Rule Set was installed on Apache and tested against SQL injection, XSS, path traversal, command injection and a scanner user-agent. In every case the CRS recognised the attack and added anomaly points to the request, and the detections could be read in both the error log and the audit log.

The difference between the two engine modes was clear. In **DetectionOnly** mode the attacks were logged but returned `200`, and the XSS payload even executed in the browser. In **On** mode the same requests were refused with `403 Forbidden`, while normal requests were unaffected. Starting in DetectionOnly mode is good practice, because it allows the logs to be reviewed for false positives before any real user can be blocked. When a false positive does occur, it can be fixed with a narrow rule exclusion, as shown in section 7.3, instead of switching the protection off. Finally, the custom rules showed that the WAF can also enforce site-specific policies, such as blocking the `/admin` path or a `debug` parameter.

The WAF is an extra layer of defence, not a replacement for secure code: the application itself should still validate input and escape output.

---

## Appendix A: Command reference

```bash
sudo ./setup_waf.sh            # install + configure (starts in DetectionOnly)
sudo ./setup_waf.sh block      # blocking ON
sudo ./setup_waf.sh detect     # log only
sudo ./test_waf.sh             # run all tests
sudo tail -f /var/log/apache2/waf-lab-error.log      # live WAF log
sudo tail -f /var/log/apache2/modsec_audit.log       # live audit log
sudo apachectl configtest && sudo apachectl -k graceful   # reload after editing rules
```

## Appendix B: Common issues and fixes

| Problem | Fix |
|---|---|
| `sudo: ./setup_waf.sh: command not found` or `Permission denied` | Run `chmod +x setup_waf.sh test_waf.sh`, and run it from inside the `waf-lab` folder |
| `$'\r': command not found` | The file has Windows line endings. Run `sed -i 's/\r$//' setup_waf.sh test_waf.sh` |
| `apt-get update` shows errors for another repository | Ignore if the packages still install. Otherwise fix or disable that repo in `/etc/apt/sources.list.d/` |
| `http://localhost:8080` does not open | `sudo apachectl configtest`, then `sudo tail -n 30 /var/log/apache2/error.log`. Check that the port is free: `sudo ss -ltnp \| grep 8080` |
| Port 8080 is already in use | Use another port: `sudo SITE_PORT=8081 ./setup_waf.sh` and then `SITE_PORT=8081 ./test_waf.sh` |
| Browser on the host can't reach the VM | Use the VM's IP (`hostname -I`), set the VM network to *Bridged* or *Host-only*, and allow the port: `sudo ufw allow 8080/tcp` |
| Attacks return 200 in blocking mode | Check that `grep ^SecRuleEngine /etc/modsecurity/modsecurity.conf` shows `On`, then `sudo apachectl -k restart` |
| `test_waf.sh` cannot read the log | Run it with `sudo ./test_waf.sh` |
| Everything returns 403, even normal pages | Run `sudo grep ModSecurity /var/log/apache2/waf-lab-error.log \| tail` to see which rule fired, then tune it (section 7.3) |
| No Linux machine/VM available | Use VirtualBox or WSL2 with Ubuntu. On WSL without systemd the script falls back to `apachectl` automatically |

## Appendix C: Cleanup

After the screenshots were taken, the lab was removed:

```bash
sudo a2dissite waf-lab
sudo rm -rf /var/www/waf-lab /etc/apache2/sites-available/waf-lab.conf
sudo systemctl restart apache2     # or: sudo apachectl -k restart
```

To remove the packages completely: `sudo apt-get remove --purge apache2 libapache2-mod-security2 modsecurity-crs`.

