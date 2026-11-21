#!/bin/bash
# End-to-end tests. Run on a Mac: bash tests/run.sh
# Every check is a hard assertion; the script exits non-zero on the first failure.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
FX="$ROOT/tests/fixture"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass() { printf 'ok   %s\n' "$*"; }
expect() { # expect <file> <regex> <description>
  grep -qE "$2" "$1" || { printf 'FAIL %s\n--- %s ---\n' "$3" "$1"; cat "$1"; exit 1; }
  pass "$3"
}

# --- report: markdown, offline -------------------------------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --no-twofa --out "$WORK/report.md"
expect "$WORK/report.md" '^\| Logins with a password \| 5 \|' "report counts live logins"
expect "$WORK/report.md" '^\| In trash \(ignored, empty it\) \| 1 \|' "report excludes trash"
expect "$WORK/report.md" '^\| Reused \(accounts sharing a password\) \| 3 \|' "report counts reused logins"
expect "$WORK/report.md" 'Password group 1: used 3 times' "report shows reuse count"
expect "$WORK/report.md" '^\| Weak \| 4 \|' "report counts weak"
expect "$WORK/report.md" '^\| Duplicate entries \(same site \+ username\) \| 2 \|' "report counts duplicates"
expect "$WORK/report.md" '^\| 1 - email, Apple, Google, Microsoft \| Gmail' "report ranks email first"
expect "$WORK/report.md" '^\| 5 - everything else \| Netflix' "report does not match x.com inside netflix.com"
expect "$WORK/report.md" 'not checked \(--no-hibp\)' "report marks breach check skipped"
! grep -q 'password123' "$WORK/report.md" || { echo "FAIL a password leaked into the report"; exit 1; }
pass "report never prints a password"

# --- report: breach check against Have I Been Pwned ---------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --no-twofa --out "$WORK/report-hibp.md"
expect "$WORK/report-hibp.md" '^\| Exposed in a breach \| 4 \|' "breach check flags the known-breached passwords"
expect "$WORK/report-hibp.md" '^\| Gmail \(mom@gmail.com\) - accounts.google.com \| [0-9,]+ \|' "breach table has a count"

# --- report: html -------------------------------------------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --no-twofa --html --out "$WORK/report.html"
expect "$WORK/report.html" '<strong>Logins that need a new password</strong>' "html converts bold"
expect "$WORK/report.html" '<h2>Reused passwords</h2>' "html converts headings"
expect "$WORK/report.html" '<li>Roblox \(kiddo\) - roblox.com</li>' "html converts bullets"
! grep -q '\*\*\|^| ' "$WORK/report.html" || { echo "FAIL stray markdown in html"; exit 1; }
pass "html has no stray markdown"

# --- report: the live path, through a stand-in bw that only accepts the real subcommands ----
# Pins the argv bw_report.py sends (`list` and `items` as two arguments). It cannot catch a
# change in what the real bw prints; the fixture stands in for that.
mkdir "$WORK/fakebin"
cat >"$WORK/fakebin/bw" <<EOF
#!/bin/bash
case "\$#:\$1:\$2" in
  1:status:) echo '{"status":"unlocked","serverUrl":"https://vault.bitwarden.eu"}' ;;
  1:sync:) echo 'Syncing complete.' ;;
  2:list:items) cat "$FX/items.json" ;;
  2:list:folders) cat "$FX/folders.json" ;;
  *) echo "Invalid command: \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$WORK/fakebin/bw"
PATH="$WORK/fakebin:$PATH" BW_SESSION=fake uv run --quiet bw_report.py --no-hibp --no-twofa --out "$WORK/report-live.md"
expect "$WORK/report-live.md" '^\| Logins with a password \| 5 \|' "live path reads the vault through bw list items"
expect "$WORK/report-live.md" '\[Open in Bitwarden\]\(https://vault.bitwarden.eu/#/vault\?itemId=1\)' "live path links to the web vault of the server bw reports (EU here)"

# --- report: password shapes a real vault has and the fixture lacks -----------------------
# A 200-character password (zxcvbn refuses anything over 72) and a non-ASCII one. Pins that the
# report completes and counts them; it cannot catch a shape neither of these is.
LONG_PW="$(printf 'Qx7!mZ2@%.0s' $(seq 1 25))"
/usr/bin/jq --arg long "$LONG_PW" '. + [
  {"id":"90","type":1,"name":"Long","deletedDate":null,"login":{"username":"a@b.com","password":$long,"uris":[{"uri":"https://long.example.com"}]}},
  {"id":"91","type":1,"name":"Unicode","deletedDate":null,"login":{"username":"c@d.com","password":"pässwörd-日本語-🔑","uris":[{"uri":"https://uni.example.com"}]}}
]' "$FX/items.json" >"$WORK/items-shapes.json"
uv run --quiet bw_report.py --input "$WORK/items-shapes.json" --no-hibp --no-twofa --out "$WORK/report-shapes.md"
expect "$WORK/report-shapes.md" '^\| Logins with a password \| 7 \|' "a 200-character and a non-ASCII password are scored, not fatal"

# --- report: a copy of the same account is not reuse --------------------------------------
# Copies of Gmail (inside a reuse group) and Chase (unique password): same site, username and
# password. Pins that copies add nothing to the reuse counts or the fix list; it cannot catch a
# copy whose site or username is spelled differently, which is a different account here.
/usr/bin/jq '. + [
  {"id":"92","type":1,"name":"Gmail copy","deletedDate":null,"login":{"username":"mom@gmail.com","password":"password123","uris":[{"uri":"https://accounts.google.com"}]}},
  {"id":"93","type":1,"name":"Chase copy","deletedDate":null,"login":{"username":"mom","password":"Xk9#mPq2$vL7nR4wZ!t8","uris":[{"uri":"https://chase.com"}]}}
]' "$FX/items.json" >"$WORK/items-copies.json"
uv run --quiet bw_report.py --input "$WORK/items-copies.json" --no-hibp --no-twofa --out "$WORK/report-copies.md"
expect "$WORK/report-copies.md" '^\| Reused \(accounts sharing a password\) \| 3 \|' "copies of one account do not count as reuse"
expect "$WORK/report-copies.md" '^\| \*\*Logins that need a new password\*\* \| \*\*3\*\* \|' "the fix list counts accounts (Gmail, Roblox, Netflix), not copies"

# --- report: fix order, two-step, AutoFill, old passwords, notes, links, progress -------------------
# One fixture vault (tests/fixture/health.json) with an item per case; its one "recent" item gets a
# creation date ten days back. Runs in UTC so the dates printed are the fixture's own. Cannot catch
# the real 2FA Directory list, or the real web vault's link format, changing shape.
H="$WORK/health.json"; R="$WORK/h1.md"
/usr/bin/jq --arg recent "$(date -u -v-10d +%Y-%m-%dT%H:%M:%SZ)" 'map(if .creationDate == "RECENT" then .creationDate = $recent else . end)' "$FX/health.json" >"$H"
health() { # health <vault json> <report file> <args...>; what it prints goes to <report file>.log
  local vault="$1" out="$2"; shift 2
  TZ=UTC uv run --quiet bw_report.py --input "$vault" --folders "$FX/health-folders.json" --no-hibp --out "$out" "$@" >"$out.log" 2>&1
}
section() { sed -n "/^## $1/,/^## /p" "$R"; } # one section of the report, by its heading
health "$H" "$R" --twofa-file "$FX/twofa.json" --state "$WORK/progress.json" || { cat "$R.log"; echo "FAIL the report on the health fixture"; exit 1; }

# Fix order: a listed domain or an address under it, never a word inside another name; a folder line wins.
expect "$R" '^\| 2 - money \| Forum \(a\) - forum.example.org \| weak \|' "a folder named in the fix order sets the tier, capitals ignored"
expect "$R" '^\| 5 - everything else \| Recipes \(cook\) - epicurious.com \| weak \|' "epicurious.com is not a gaming site"
expect "$R" '^\| 5 - everything else \| Lookalike \(a\) - gmail.example.com \| weak \|' "gmail.example.com is not Gmail"
expect "$R" '^\| 5 - everything else \| Webmail \(a@example.com\) - mail.example.com \| saved 2020-01-01 \|' "mail.example.com is not an email provider"
expect "$R" '^\| 1 - email, Apple, Google, Microsoft \| Google \(a@example.com\) - mail.google.com \| last changed 2021-03-03 \|' "an address under a listed domain takes its tier"
expect "$WORK/report.md" '^\| 4 - gaming and social \| Roblox' "gaming and social is the fourth tier"
echo '[{"id":"v1","type":1,"name":"Phone","deletedDate":null,"login":{"username":"a","password":"letmein","uris":[{"uri":"https://login.verizon.com"}]}}]' >"$WORK/carrier.json"
health "$WORK/carrier.json" "$WORK/carrier.md" --no-twofa
expect "$WORK/carrier.md" '^\| 3 - phone, utilities, insurance, health \| Phone \(a\) - login.verizon.com \|' "a phone carrier is the third tier"
printf '1 google.com\n2 not a domain\n' >"$WORK/bad-order.txt"
if health "$H" "$WORK/bad-order.md" --no-twofa --fix-order "$WORK/bad-order.txt"; then echo "FAIL a malformed fix-order line was accepted"; exit 1; fi
expect "$WORK/bad-order.md.log" "bad-order.txt line 2: 'not a domain' is not a domain like example.com" "a malformed fix-order line is named with its line number"
printf '1 example.com\n2 example.com\n' >"$WORK/bad-order.txt"
if health "$H" "$WORK/bad-order.md" --no-twofa --fix-order "$WORK/bad-order.txt"; then echo "FAIL a domain listed in two tiers was accepted"; exit 1; fi
expect "$WORK/bad-order.md.log" "line 2: 'example.com' is listed twice with different tiers" "a domain listed in two tiers is refused"
pass "the fix order matches listed domains and folders only"

# Two-step login: matched here against a saved copy of the list. A site counts when the list has it, an
# address under it, or (through the fix order's domain) another address of the same site.
expect "$R" '^\| Sites that offer two-step login, no code saved here \| 3 \|' "two-step login counts sites with no code saved"
expect "$R" "this site offers two-step login; check it's on" "the two-step wording does not claim to know whether it is on"
section 'Two-step login' >"$WORK/twofa-section.md"
expect "$WORK/twofa-section.md" '^\| 2 - money \| Chase \(a\) - secure.chase.com \|' "an address under a site on the list is flagged"
expect "$WORK/twofa-section.md" '^\| 1 - email, Apple, Google, Microsoft \| Apple \(a@example.com\) - idmsa.apple.com \|' "another address of a listed site is flagged through the fix order's domain"
expect "$WORK/twofa-section.md" '^\| 5 - everything else \| Parent site \(a\) - example.io \|' "a site whose sign-in address is on the list is flagged"
! grep -q '| Google (a@\|Plain site\|Lookalike\|Webmail' "$WORK/twofa-section.md" || { cat "$WORK/twofa-section.md"; echo "FAIL a login with a code saved, a site with no two-step login, or an unrelated site was flagged"; exit 1; }
expect "$R" 'Data sourced from \[2FA Directory\]\(https://2fa.directory/\) by 2factorauth' "the list's source is credited, as its licence asks"
health "$H" "$WORK/h-nolist.md" --twofa-file "$WORK/no-such-list.json" || { cat "$WORK/h-nolist.md.log"; echo "FAIL a missing two-step list stopped the report"; exit 1; }
expect "$WORK/h-nolist.md" '^\| Sites that offer two-step login, no code saved here \| not checked \(the list of sites could not be downloaded\) \|' "a list that cannot be had shows as not checked, never as zero"
expect "$WORK/h-nolist.md" '^Not checked this time: the list of sites could not be downloaded\.$' "the two-step section says it was not checked"
expect "$WORK/h-nolist.md.log" 'The two-step check was skipped' "a skipped two-step check is said on the terminal too"
# The real download: the whole public list, kept for a day. A fresh copy is used as it is; a stale one is replaced.
CACHE="$WORK/twofa-cache.json"
health "$H" "$WORK/h-live.md" --twofa-cache "$CACHE" || { cat "$WORK/h-live.md.log"; echo "FAIL the report with the downloaded list"; exit 1; }
[ "$(/usr/bin/jq 'type == "object" and length > 1000' "$CACHE")" = "true" ] || { echo "FAIL the downloaded two-step list was not kept, or is not the shape expected"; exit 1; }
expect "$WORK/h-live.md" '^\| Sites that offer two-step login, no code saved here \| [0-9]+ \|' "the downloaded list is used"
cp "$FX/twofa.json" "$CACHE"
health "$H" "$WORK/h-cached.md" --twofa-cache "$CACHE"
cmp -s "$FX/twofa.json" "$CACHE" || { echo "FAIL a copy of the list younger than a day was downloaded again"; exit 1; }
expect "$WORK/h-cached.md" '^\| Sites that offer two-step login, no code saved here \| 3 \|' "a fresh kept copy of the list is the one used"
touch -t "$(date -v-2d +%Y%m%d%H%M)" "$CACHE"
health "$H" "$WORK/h-stale.md" --twofa-cache "$CACHE"
! cmp -s "$FX/twofa.json" "$CACHE" || { echo "FAIL a copy of the list older than a day was not replaced"; exit 1; }
pass "two-step login is matched locally against the whole list, kept for a day"

# AutoFill, old passwords, notes.
expect "$R" '^\| AutoFill problems \| 2 \|' "AutoFill problems are counted"
expect "$R" '^\| Garage code \| no web address saved \| \[Open in Bitwarden\]\(https://vault.bitwarden.com/#/vault\?itemId=h7\) \|$' "a login with no address is flagged, with only the Bitwarden link"
expect "$R" '^\| Router \(admin\) - router.example.lan \| only an http:// address saved \|' "a login with only an http:// address is flagged"
! section 'AutoFill problems' | grep -q 'Bank app' || { echo "FAIL a login that also has an https:// address was flagged"; exit 1; }
expect "$R" '^\| Passwords unchanged for 3\+ years \| 2 \|' "old passwords are counted"
expect "$R" 'Importing passwords resets these dates, so right after an import nothing is old yet' "the report says an import resets the dates"
expect "$R" '^1 login\(s\) were added in the last 30 days' "a login added in the last 30 days is counted apart"
! section 'Passwords unchanged' | grep -q 'Recipes' || { echo "FAIL a login added ten days ago was judged old by its password date"; exit 1; }
expect "$R" '^\| Notes that may hold a password \| 2 \|' "notes that may hold a password are counted"
expect "$R" '^\| Wifi details \| secure note \| a line that looks like a saved password or PIN \|' "a secure note with a password line is flagged by name and reason"
expect "$R" '^\| Old forum \| login \| a line shaped like username:password \|' "a login's note with a username:password line is flagged"
! section 'Notes that may hold' | grep -q 'Shopping list\|Trashed' || { echo "FAIL an ordinary note or a trashed item was flagged"; exit 1; }
expect "$R" 'cannot see whether your Bitwarden email address is verified, or whether two-step login is turned on' "the report says it cannot check the Bitwarden account itself"
expect "$R" '^- \[Two-step login\]\(https://vault.bitwarden.com/#/settings/security/two-factor\)' "it links to the two-step setting instead"
expect "$R" '^- \[Account settings\]\(https://vault.bitwarden.com/#/settings/account\)' "it links to the account page for email verification"
pass "AutoFill, old passwords, notes and the account pointers are reported"

# Links: built from the saved address and the item id only. Nothing in the vault can add a link of its own.
expect "$R" '^\| 2 - money \| Forum .* \| \[Change password\]\(https://forum.example.org/.well-known/change-password\), \[Site\]\(https://forum.example.org/\), \[Open in Bitwarden\]\(https://vault.bitwarden.com/#/vault\?itemId=h5\) \|$' "a flagged login links to its change-password page, its site and its Bitwarden entry"
TZ=UTC uv run --quiet bw_report.py --input "$H" --folders "$FX/health-folders.json" --no-hibp --twofa-file "$FX/twofa.json" --html --vault-url https://bw.example.org:8443/base/ --out "$WORK/h.html" >/dev/null
expect "$WORK/h.html" '<a href="https://bw.example.org:8443/base/#/vault\?itemId=h5" rel="noreferrer noopener">Open in Bitwarden</a>' "the Bitwarden link uses the account's own server"
expect "$WORK/h.html" '<a href="https://forum.example.org/.well-known/change-password" rel="noreferrer noopener">Change password</a>' "html turns the links into links"
! grep -q 'href="https://evil.example' "$WORK/h.html" || { echo "FAIL an item name became a link"; exit 1; }
! grep -q '\*\*\|^| \|\](http' "$WORK/h.html" || { grep -n '\*\*\|^| \|\](http' "$WORK/h.html" | head -3; echo "FAIL stray markdown in the html"; exit 1; }
health "$H" "$WORK/h-oddvault.md" --no-twofa --vault-url 'javascript:alert(1)'
! grep -q 'Open in Bitwarden\|javascript' "$WORK/h-oddvault.md" || { echo "FAIL a server address that is not a plain web address was put in a link"; exit 1; }
expect "$WORK/h-oddvault.md" 'In the Bitwarden web vault, open Settings, then Security, then Two-step login' "without a usable server address the account pointers are words, not links"
pass "links come from the saved address, the item id and the server only"

# Progress: the file holds item ids and reason names, nothing else, and the next run compares against it.
expect "$R" '^\*\*First check-up of this vault on this Mac: 13 flagged\.\*\*' "a first run says so and counts what is flagged"
P="$WORK/progress.json"
[ "$(stat -f %Lp "$P")" = "600" ] || { echo "FAIL the progress file is not owner-only"; exit 1; }
[ "$(/usr/bin/jq -c --slurpfile vault "$H" '[(keys == ["checks","date","flagged","version"]), ((.flagged | keys) - ($vault[0] | map(.id)) == []), ([.flagged[][], .checks[]] | all(IN("exposed","reused","weak","duplicate","two-step","autofill","old","notes"))), (.flagged | length == 13), (.flagged.h5 == ["weak"]), (.checks | index("exposed") == null)]' "$P")" = "[true,true,true,true,true,true]" ] || { cat "$P"; echo "FAIL the progress file must hold item ids and reason names only, and only the checks that ran"; exit 1; }
! grep -qi 'forum\|example\|chase\|password1\|Hunter2\|jsmith\|Zr8' "$P" || { echo "FAIL a name, site, username or password reached the progress file"; exit 1; }
# Second run: Forum's password and the Wifi note are fixed; Bank app loses its https:// address.
/usr/bin/jq 'map(if .id == "h5" then .login.password = "Zr8#kLm2$Qv9xT4w-05" elif .id == "h9" then .notes = "nothing here" elif .id == "h8" then .login.uris = [{"uri":"http://bank.example.com"}] else . end)' "$H" >"$WORK/health2.json"
health "$WORK/health2.json" "$WORK/h2.md" --twofa-file "$FX/twofa.json" --state "$P"
expect "$WORK/h2.md" '^\*\*2 fixed since [0-9]{4}-[0-9]{2}-[0-9]{2}, 12 left\.\*\* 1 new since then, marked NEW\.$' "the next run counts what was fixed, what is left and what is new"
expect "$WORK/h2.md" '^\| Bank app \(a\) - bank.example.com \*\*NEW\*\* \| only an http:// address saved \|' "a newly flagged login is marked NEW"
[ "$(grep -c 'NEW\*\*' "$WORK/h2.md")" = "1" ] || { grep 'NEW' "$WORK/h2.md"; echo "FAIL a login flagged before was marked NEW"; exit 1; }
# Third run without the two-step check: the three logins only it flags are neither fixed nor new.
health "$WORK/health2.json" "$WORK/h3.md" --no-twofa --state "$P"
expect "$WORK/h3.md" '^\*\*0 fixed since [0-9]{4}-[0-9]{2}-[0-9]{2}, 9 left\.\*\*$' "a check that did not run is not counted as fixed"
echo '{"flagged": []}' >"$WORK/bad-progress.json"
if health "$H" "$WORK/h-badstate.md" --no-twofa --state "$WORK/bad-progress.json"; then echo "FAIL a progress file of the wrong shape was accepted"; exit 1; fi
expect "$WORK/h-badstate.md.log" 'is not a progress file this script wrote' "a progress file of the wrong shape is refused"
! grep -rq 'Hunter2-note-secret\|Tr0ub4dor-note-pair\|Trashed-note-secret\|HomeNet\|Zr8#kLm2\|password1\|letmein\|monkey12\|qwerty123' "$WORK"/h*.md "$WORK"/h*.log "$WORK/h.html" "$P" || { echo "FAIL a password or a note's text reached a report, the terminal or the progress file"; exit 1; }
pass "progress is kept as item ids and reasons only; no password or note text is ever written"

# --- import diff --------------------------------------------------------------------------
uv run --quiet bw_import_diff.py "$FX/chrome.csv" "$FX/apple.csv" "$FX/chrome2.csv" --vault "$FX/items.json" --out-dir "$WORK/import" >/dev/null
expect "$WORK/import/conflicts.md" 'New, written to .*: \*\*4\*\*' "diff finds 4 new (3 Target rows collapse to 1, Patreon from the second account)"
expect "$WORK/import/conflicts.md" 'identical, skipped: 2' "diff skips identical entries"
expect "$WORK/import/conflicts.md" 'Conflicts, decide by hand: 2' "diff counts vault and export conflicts together"
expect "$WORK/import/conflicts.md" '^\| netflix.com \| MOM@gmail.com \| chrome.csv \| Netflix, netflix.com \|' "conflict names both vault items"
expect "$WORK/import/conflicts.md" '^\| target.com \| mom@gmail.com \| chrome.csv \| chrome2.csv \|' "export conflict: newer file wins, older named"
expect "$WORK/import/new-for-bitwarden.csv" '^folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp$' "csv has the Bitwarden header"
PATH="$WORK/fakebin:$PATH" BW_SESSION=fake uv run --quiet bw_import_diff.py "$FX/chrome.csv" "$FX/apple.csv" "$FX/chrome2.csv" --out-dir "$WORK/import-live" >/dev/null
diff "$WORK/import/conflicts.md" <(sed 's#/import-live/#/import/#' "$WORK/import-live/conflicts.md") || { echo "FAIL live diff differs from the --vault diff"; exit 1; }
pass "diff reads the live vault through bw list items, same result as --vault"
[ "$(wc -l <"$WORK/import/new-for-bitwarden.csv" | tr -d ' ')" = "5" ] || { echo "FAIL csv row count"; exit 1; }
grep -q 'Tgt-9988-xyz' "$WORK/import/new-for-bitwarden.csv" || { echo "FAIL newer export password must be the one imported"; exit 1; }
! grep -q 'OLD-target-pw' "$WORK/import/new-for-bitwarden.csv" || { echo "FAIL older export password must not be imported"; exit 1; }
pass "csv holds exactly the 4 new rows, newest export wins a disagreement"

# --- a malformed URL (an unclosed IPv6 bracket) in a real vault or export must not abort the run ----
# Pins that the report and the diff complete and count the entry; it cannot catch another shape of bad URL.
/usr/bin/jq '. + [{"id":"95","type":1,"name":"Bad URL","deletedDate":null,"login":{"username":"bad@x.com","password":"Zq4!rT8#wN2$vB6","uris":[{"uri":"http://[fe80::1"}]}}]' "$FX/items.json" >"$WORK/items-badurl.json"
uv run --quiet bw_report.py --input "$WORK/items-badurl.json" --no-hibp --no-twofa --out "$WORK/report-badurl.md"
expect "$WORK/report-badurl.md" '^\| Logins with a password \| 6 \|' "the report survives a malformed URL"
printf 'name,url,username,password,note\nBad URL,http://[fe80::1,bad@x.com,Zq4!rT8#wN2$vB6,\n' >"$WORK/badurl.csv"
uv run --quiet bw_import_diff.py "$WORK/badurl.csv" --vault "$FX/items.json" --out-dir "$WORK/import-badurl" >/dev/null
expect "$WORK/import-badurl/conflicts.md" 'New, written to .*: \*\*1\*\*' "the diff survives a malformed URL and imports the entry"
[ "$(stat -f %Lp "$WORK/import/new-for-bitwarden.csv")" = "600" ] || { echo "FAIL csv is not owner-only"; exit 1; }
pass "csv is owner-read-only"
! grep -q 'DifferentPw1' "$WORK/import/conflicts.md" || { echo "FAIL conflict password leaked"; exit 1; }
pass "conflicts never print a password"

# --- installer: fresh home, no Homebrew, files served from this checkout -------------------
FAKE_HOME="$WORK/home"
mkdir -p "$FAKE_HOME/Desktop" "$FAKE_HOME/Downloads"
HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash bw-health.sh check >"$WORK/install.log" 2>&1 \
  || { cat "$WORK/install.log"; echo "FAIL installer check"; exit 1; }
expect "$WORK/install.log" 'Installed OK' "installer completes"
expect "$WORK/install.log" '^[0-9]{4}\.[0-9]+\.[0-9]+$' "installer prints the bw version"
expect "$WORK/install.log" '^uv [0-9]' "installer prints the uv version"
[ -x "$FAKE_HOME/Library/Application Support/bw-health/bin/bw" ] || { echo "FAIL bw not installed"; exit 1; }
APP="$FAKE_HOME/Library/Application Support/bw-health"
VERSION="$(sed -n 's/^VERSION="\(.*\)"$/\1/p' bw-health.sh)"; FILES="$(sed -n 's/^FILES="\(.*\)"$/\1/p' bw-health.sh)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ -n "$FILES" ] || { echo "FAIL bw-health.sh must name its VERSION (X.Y.Z) and its FILES"; exit 1; }
for f in $FILES; do [ -f "$APP/$f" ] || { echo "FAIL $f was not fetched"; exit 1; }; done
pass "installer put bw and every fetched file in the app folder"
[ "$(sed -n 2p "$WORK/install.log")" = "==> bw-health v$VERSION. The line that always runs exactly this version:" ] || { head -4 "$WORK/install.log"; echo "FAIL a fetched run must open with its version, before anything is installed"; exit 1; }
pass "a fetched run opens with its version"
expect "$WORK/install.log" "^    curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v$VERSION/bw-health.sh \| bash$" "and shows the paste line pinned to that version's tag"
HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash bw-health.sh check >"$WORK/install2.log" 2>&1
! grep -q 'Installing' "$WORK/install2.log" || { echo "FAIL second run re-installed"; exit 1; }
pass "second run skips installs"

# A copy of the installer with every pinned hash zeroed must refuse the download and install nothing.
# Cannot catch a pin that is correct for one architecture and wrong for the other (CI runs one).
BAD_HOME="$WORK/bad-home"
mkdir -p "$BAD_HOME/.local/bin" "$BAD_HOME/Desktop"
ln -s "$FAKE_HOME/.local/bin/uv" "$BAD_HOME/.local/bin/uv"
sed -E 's/"[0-9a-f]{64}"/"0000000000000000000000000000000000000000000000000000000000000000"/' bw-health.sh >"$WORK/bw-health-bad-pin.sh"
! cmp -s bw-health.sh "$WORK/bw-health-bad-pin.sh" || { echo "FAIL test setup: no pinned hash was replaced"; exit 1; }
if HOME="$BAD_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash "$WORK/bw-health-bad-pin.sh" check >"$WORK/bad-pin.log" 2>&1; then
  cat "$WORK/bad-pin.log"; echo "FAIL installer accepted a download that does not match its pinned checksum"; exit 1
fi
expect "$WORK/bad-pin.log" 'did not match its checksum' "installer refuses a download that fails its checksum"
[ ! -e "$BAD_HOME/Library/Application Support/bw-health/bin/bw" ] || { echo "FAIL bw installed despite a bad checksum"; exit 1; }
pass "nothing is installed when the checksum fails"

# --- releases: every fetched file is pinned by checksum, and a tagged version is frozen ---------------
for f in $FILES; do
  sum="$(shasum -a 256 "$f" | cut -d' ' -f1)"
  grep -qE "^ +$f\) +echo \"$sum\" ;;$" bw-health.sh || { echo "FAIL the checksum of $f written in bw-health.sh is stale. Its line must read:"; echo "    $f) echo \"$sum\" ;;"; exit 1; }
done
pass "every fetched file matches the checksum written in bw-health.sh"
# Asks origin, so a clone without tags (CI) is judged the same way. Cannot catch a tag that was moved.
tagged=0; git ls-remote --exit-code --tags origin "refs/tags/v$VERSION" >/dev/null 2>&1 || tagged=$?
case "$tagged" in
  0)
    git fetch -q origin "refs/tags/v$VERSION:refs/tags/v$VERSION"
    # shellcheck disable=SC2086
    git diff --quiet "v$VERSION" -- bw-health.sh $FILES || { echo "FAIL bw-health.sh or a file it fetches changed after v$VERSION was tagged. Raise VERSION: a released version never changes."; exit 1; }
    pass "nothing the paste line runs has changed since v$VERSION was tagged" ;;
  2) pass "v$VERSION is not tagged yet, so it may still change" ;;
  *) echo "FAIL could not ask origin whether v$VERSION is tagged"; exit 1 ;;
esac
# A served file that differs by one line is refused, never installed, and nothing is left half-written.
for f in bw_dedupe.py fix_order.txt; do
  rm -rf "$WORK/served"; mkdir "$WORK/served"
  # shellcheck disable=SC2086
  cp $FILES "$WORK/served/"; echo '# one line more' >>"$WORK/served/$f"; cp "$APP/$f" "$WORK/installed-before"
  if HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$WORK/served" /bin/bash bw-health.sh check >"$WORK/tamper.log" 2>&1; then
    cat "$WORK/tamper.log"; echo "FAIL a changed $f was accepted"; exit 1
  fi
  expect "$WORK/tamper.log" "$f did not match the checksum written in bw-health.sh, so it was not used" "a fetched $f that fails its checksum is refused by name"
  cmp -s "$APP/$f" "$WORK/installed-before" && [ ! -e "$APP/$f.new" ] || { echo "FAIL a $f that failed its checksum was installed or left behind"; exit 1; }
done
! grep -q 'bw-health/main' bw-health.sh README.md || { grep -n 'bw-health/main' bw-health.sh README.md; echo "FAIL the tool or its README still points at main"; exit 1; }
pass "a file that fails its checksum is not used, and nothing points at main"

# --- installer: staging exports from Downloads (run under the Mac's own bash 3.2) ----------
DL="$FAKE_HOME/Downloads"; IMP="$FAKE_HOME/Library/Application Support/bw-health/Bitwarden Import"; TODAY="$(date +%Y-%m-%d)"
cp "$FX/chrome.csv" "$DL/Google Passwords.csv"
cp "$FX/chrome.csv" "$DL/Google Passwords (1).csv"; touch -t "$(date -v-2d +%Y%m%d%H%M)" "$DL/Google Passwords (1).csv"
cp "$FX/apple.csv" "$DL/Passwords.csv"; touch -t "$(date -v-10d +%Y%m%d%H%M)" "$DL/Passwords.csv"
printf 'url,title\nhttps://x.com,not a password file\n' >"$DL/other.csv"
printf 'skip\n' >"$WORK/tty"
stage() { HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$ROOT" BW_HEALTH_TTY="$1" /bin/bash bw-health.sh exports; }

D2="$(date -v-2d +%Y-%m-%d)"; D10="$(date -v-10d +%Y-%m-%d)"
stage "$WORK/tty" >"$WORK/stage1.log" 2>&1 || { cat "$WORK/stage1.log"; echo "FAIL stage 1"; exit 1; }
expect "$WORK/stage1.log" "Moved Google Passwords.csv to Bitwarden Import/chrome-passwords-$TODAY.csv" "newest fresh Chrome export is moved and renamed"
expect "$WORK/stage1.log" "Moved Google Passwords \(1\).csv to Bitwarden Import/chrome-passwords-$D2.csv" "older Chrome copy is moved too"
expect "$WORK/stage1.log" "Moved Passwords.csv to Bitwarden Import/apple-passwords-$D10.csv" "stale Apple export is moved too"
[ "$(tail -2 "$WORK/stage1.log" | tr '\n' ' ')" = "$IMP/chrome-passwords-$TODAY.csv $IMP/chrome-passwords-$D2.csv " ] || { tail -3 "$WORK/stage1.log"; echo "FAIL every fresh export feeds the diff, newest first"; exit 1; }
for f in "chrome-passwords-$TODAY" "chrome-passwords-$D2" "apple-passwords-$D10"; do
  [ -f "$IMP/$f.csv" ] || { echo "FAIL $f.csv missing from the import folder"; exit 1; }
  [ "$(stat -f %Lp "$IMP/$f.csv")" = "600" ] || { echo "FAIL $f.csv not owner-only"; exit 1; }
done
[ "$(ls "$DL")" = "other.csv" ] || { ls "$DL"; echo "FAIL every password export must leave Downloads; unrelated csv stays"; exit 1; }
! grep -q 'Press Return' "$WORK/stage1.log" || { echo "FAIL no prompt expected when a fresh export exists"; exit 1; }
[ -z "$(ls "$FAKE_HOME/Desktop" 2>/dev/null | grep -v 'Bitwarden Report')" ] || { echo "FAIL plain-text files must never land on the Desktop (iCloud sync)"; exit 1; }
pass "every export leaves Downloads; every fresh one feeds the diff newest first; nothing on the Desktop"

cp "$FX/apple.csv" "$DL/Passwords.csv"; touch -t "$(date -v-10d +%Y%m%d%H%M)" "$DL/Passwords.csv"
stage "$WORK/tty" >"$WORK/stage2.log" 2>&1 || { cat "$WORK/stage2.log"; echo "FAIL stage 2"; exit 1; }
expect "$WORK/stage2.log" 'Passwords.csv \(apple, from .*\) is older than 7 days' "stale export is named with its date"
expect "$WORK/stage2.log" 'Skipping the import step' "typing skip ends the import step"
[ -f "$IMP/apple-passwords-$D10-2.csv" ] || { ls "$IMP"; echo "FAIL stale file must still be moved, with a -2 suffix on a name clash"; exit 1; }
[ ! -e "$DL/Passwords.csv" ] || { echo "FAIL stale file left in Downloads"; exit 1; }
pass "stale-only Downloads prompts for a re-export, honours skip, and still moves the stale file"

mkfifo "$WORK/fifo"
( sleep 1; cp "$FX/apple.csv" "$DL/Passwords.csv"; printf '\n' >"$WORK/fifo" ) &
stage "$WORK/fifo" >"$WORK/stage3.log" 2>&1 || { cat "$WORK/stage3.log"; echo "FAIL stage 3"; exit 1; }
wait
expect "$WORK/stage3.log" "Moved Passwords.csv to Bitwarden Import/apple-passwords-$TODAY.csv" "after Return, the fresh re-export is picked up"
[ "$(tail -1 "$WORK/stage3.log")" = "$IMP/apple-passwords-$TODAY.csv" ] || { echo "FAIL re-export not staged for the diff"; exit 1; }
pass "re-export after the prompt is staged"

stage "$WORK/tty" >"$WORK/stage4.log" 2>&1 || { cat "$WORK/stage4.log"; echo "FAIL stage 4"; exit 1; }
expect "$WORK/stage4.log" 'No password export from the last 7 days' "empty Downloads prompts"
expect "$WORK/stage4.log" 'Skipping the import step' "empty Downloads plus skip exits cleanly"
pass "nothing to stage is handled"

# --- dedupe: exact and merge stages, through a stand-in bw that keeps state ------------------------
# The stand-in applies edit (JSON on stdin) and delete (soft: sets deletedDate) to a state file,
# rejects every other call (--permanent included) and logs argv. It cannot catch the real bw behaving
# differently from this model; the first real run, limited to one group, is that check.
mkdir "$WORK/fakebin-state"
cat >"$WORK/fakebin-state/bw" <<'EOF'
#!/bin/bash
echo "$*" >>"$FAKE_BW_LOG"
case "$#:$1:$2" in
  1:status:) echo '{"status":"unlocked"}' ;;
  1:sync:) echo 'Syncing complete.' ;;
  2:list:items) cat "$FAKE_BW_STATE" ;;
  2:list:folders) cat "$FAKE_BW_FOLDERS" ;;
  3:get:item) /usr/bin/jq --arg id "$3" '.[] | select(.id == $id)' "$FAKE_BW_STATE" ;;
  3:edit:item)
    new="$(base64 --decode)"
    case "${FAKE_BW_EDIT_BUG:-}" in
      drop-passkey) new="$(/usr/bin/jq 'del(.login.fido2Credentials)' <<<"$new")" ;;
      blank-password) new="$(/usr/bin/jq '.login.password = ""' <<<"$new")" ;;
      rewrite-rpid) new="$(/usr/bin/jq '.login.fido2Credentials[0].rpId = "other.example.com"' <<<"$new")" ;;
      drop-fields) new="$(/usr/bin/jq '.fields = []' <<<"$new")" ;;
      rename) new="$(/usr/bin/jq '.name = "Renamed by bw"' <<<"$new")" ;;
      unfavorite) new="$(/usr/bin/jq '.favorite = false' <<<"$new")" ;;
    esac
    /usr/bin/jq --arg id "$3" --argjson new "$new" 'map(if .id == $id then $new else . end)' "$FAKE_BW_STATE" >"$FAKE_BW_STATE.tmp" \
      && mv "$FAKE_BW_STATE.tmp" "$FAKE_BW_STATE" && echo '{}' ;;
  3:delete:item)
    /usr/bin/jq --arg id "$3" 'map(if .id == $id then .deletedDate = "2026-10-26T00:00:00Z" else . end)' "$FAKE_BW_STATE" >"$FAKE_BW_STATE.tmp" \
      && mv "$FAKE_BW_STATE.tmp" "$FAKE_BW_STATE" ;;
  *) echo "Invalid command: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$WORK/fakebin-state/bw"
STATE="$WORK/vault-state.json"; BWLOG="$WORK/bw-calls.log"; PLANS="$WORK/dedupe-plan"
cp "$FX/dupes.json" "$STATE"; : >"$BWLOG"
printf 'no\n' >"$WORK/tty-no"; printf 'DEDUPE\n' >"$WORK/tty-yes"
dedupe() { # dedupe <tty file> <args...>
  local tty="$1"; shift
  PATH="$WORK/fakebin-state:$PATH" BW_SESSION=fake FAKE_BW_STATE="$STATE" FAKE_BW_FOLDERS="$FX/folders.json" FAKE_BW_LOG="$BWLOG" BW_HEALTH_TTY="$tty" \
    uv run --quiet bw_dedupe.py "$@" --out-dir "$PLANS"
}
live() { /usr/bin/jq --arg re "$1" '[.[] | select(.deletedDate == null) | select(.id | test($re))] | length' "$STATE"; }
vault() { /usr/bin/jq -r --arg id "$1" ".[] | select(.id == \$id) | $2" "$STATE"; }

cp "$STATE" "$WORK/state-before.json"
dedupe "$WORK/tty-no" exact >"$WORK/dd1.log" 2>&1 || { cat "$WORK/dd1.log"; echo "FAIL exact dry run"; exit 1; }
dedupe "$WORK/tty-no" merge >"$WORK/dd2.log" 2>&1 || { cat "$WORK/dd2.log"; echo "FAIL merge dry run"; exit 1; }
expect "$WORK/dd1.log" '^2 group\(s\) to change, 9 left alone, 8 for another stage' "exact stage counts its groups, the blocked ones and the merge ones"
expect "$WORK/dd2.log" '^8 group\(s\) to change, 9 left alone, 2 for another stage' "merge stage counts its groups"
expect "$WORK/dd1.log" 'Nothing was changed' "a dry run says it changed nothing"
[ "$(grep -n 'PREVIEW ONLY' "$WORK/dd1.log" | head -1 | cut -d: -f1)" = "1" ] || { head -3 "$WORK/dd1.log"; echo "FAIL the preview-only notice must be the first line a dry run prints"; exit 1; }
expect "$WORK/dd1.log" 'PREVIEW ONLY: this step does not change, merge or delete anything' "a dry run opens by saying it is only a preview"
cmp -s "$STATE" "$WORK/state-before.json" || { echo "FAIL a dry run changed the vault"; exit 1; }
! grep -qE '^(edit|delete) ' "$BWLOG" || { cat "$BWLOG"; echo "FAIL a dry run called edit or delete"; exit 1; }
pass "dry runs change nothing"
for why in 'has an attachment' 'several copies hold a passkey' 'a passkey that bw listed without its key' 'a copy has password history the kept copy lacks' 'different passwords' 'different one-time-code seeds' 'shared with an organization' 'a custom field with different values' 'the same URL with different match settings'; do
  expect "$PLANS/plan-exact.md" "$why" "plan says why a group is left alone: $why"
done
expect "$PLANS/plan-exact.md" '^\| hulu.com \(exact@x.com\) \| 2 \|' "plan names the account to change"
expect "$PLANS/plan-exact.md" 'Hu/lu' "a pipe in a name cannot break the plan table"
! grep -q "$(printf '\033')" "$PLANS/plan-exact.md" || { echo "FAIL a terminal escape reached the plan file"; exit 1; }
expect "$PLANS/plan-merge.md" 'folders differ' "plan says when the kept folder wins"
! grep -q 'PW-secret\|secret note' "$PLANS/plan-exact.md" "$PLANS/plan-merge.md" || { echo "FAIL a password or note reached a plan file"; exit 1; }
pass "plans never carry a password or a note"

# What apply is about to do is printed, group by group, before the confirmation is asked for.
expect "$WORK/dd2.log" 'Preview: the first 3 of 8 groups' "a dry run previews a few groups and says the plan holds the rest"
expect "$WORK/dd2.log" '^\[1/8\] alpha.example.com \(case@x.com\)' "a dry run shows those groups in full, numbered out of the total"
expect "$WORK/dd2.log" 'TRASH +"Etsy" +folder: no folder' "a dry run shows the copy it would trash"
expect "$WORK/dd2.log" 'Left alone: .*different passwords' "a dry run says why groups are left alone"
expect "$PLANS/plan-merge.md" '^\| folder.example.com \(f@x.com\) \| 2 \|.*Chrome.*Apple' "the plan names the kept and the trashed folder"
if dedupe "$WORK/tty-no" merge --apply --limit 4 >"$WORK/dd-preview.log" 2>&1; then echo "FAIL preview run was confirmed"; exit 1; fi
expect "$WORK/dd-preview.log" 'Acting on 4 of 8 groups' "apply says how many groups it will act on"
expect "$WORK/dd-preview.log" 'Nothing in your vault changes until you have read the list below and typed DEDUPE' "apply opens by saying nothing changes before the typed word"
! grep -q 'PREVIEW ONLY' "$WORK/dd-preview.log" || { echo "FAIL an apply run must not claim to be preview-only"; exit 1; }
expect "$WORK/dd-preview.log" '^\[1/4\] alpha.example.com \(case@x.com\)' "apply numbers each group with its account"
expect "$WORK/dd-preview.log" 'KEEP +"Etsy shop" +folder: no folder +2 URLs' "apply shows the copy it keeps, with folder and URL count"
expect "$WORK/dd-preview.log" 'TRASH +"Etsy" +folder: no folder +2 URLs' "apply shows the copy it trashes"
expect "$WORK/dd-preview.log" 'ADDS +\+1 URL \(https://m.etsy.com/\), notes joined, marked favorite, master password re-prompt turned on$' "apply shows exactly what the kept copy gains, flags included"
! grep -q 'TOKEN123' "$WORK/dd-preview.log" "$WORK/dd2.log" "$PLANS/plan-merge.md" || { echo "FAIL a URL query string reached the terminal or the plan"; exit 1; }
pass "a URL's query string (it can carry a token) is not shown"
expect "$WORK/dd-preview.log" 'KEEP +"Folders" +folder: Chrome' "apply shows the kept folder by name"
expect "$WORK/dd-preview.log" 'TRASH +"Folders" +folder: Apple' "apply shows the trashed copy's folder by name"
expect "$WORK/dd-preview.log" 'This will edit 2 kept copies and move 4 copies to the Bitwarden trash' "the prompt states the edits and the trashing"
expect "$WORK/dd-preview.log" 'Not confirmed' "the previewed run still stops without the word"
! grep -q 'PW-secret\|secret note' "$WORK/dd-preview.log" "$WORK/dd2.log" || { echo "FAIL a password or note reached the terminal output"; exit 1; }
pass "the terminal output never carries a password or a note"

if dedupe "$WORK/tty-no" merge --apply --limit 6 >"$WORK/dd-preview2.log" 2>&1; then echo "FAIL preview run was confirmed"; exit 1; fi
expect "$WORK/dd-preview2.log" 'KEEP +"Passkey only"' "a passkey copy is the one shown as kept"
expect "$WORK/dd-preview2.log" 'TRASH +"Password only"' "the password-only copy is the one shown as trashed"
expect "$WORK/dd-preview2.log" 'ADDS +password taken from another copy' "the preview says the kept copy takes the other copy's password"
expect "$WORK/dd-preview2.log" 'could already be changed: keep the original in Apple Passwords or Chrome' "a passkey group warns that the edit cannot be undone by the read-back"
! grep -q 'KEYDATA\|PW-secret' "$WORK/dd-preview2.log" || { echo "FAIL a passkey key or password reached the preview"; exit 1; }
pass "a passkey group is previewed with its warning, and no key or password is shown"

if dedupe "$WORK/tty-no" exact --apply >"$WORK/dd3.log" 2>&1; then cat "$WORK/dd3.log"; echo "FAIL apply went ahead without the confirmation word"; exit 1; fi
expect "$WORK/dd3.log" 'Not confirmed' "apply stops unless the word is typed"
cmp -s "$STATE" "$WORK/state-before.json" || { echo "FAIL an unconfirmed apply changed the vault"; exit 1; }
if dedupe "$WORK/tty-yes" merge --apply --limit 0 >"$WORK/dd4.log" 2>&1; then echo "FAIL --limit 0 accepted"; exit 1; fi
pass "no change without the confirmation word; --limit 0 refused"

LEFT_BEFORE="$(live '^(m|c|f|l|g|h|b[124-8]|p|u|n)')"
dedupe "$WORK/tty-yes" exact --apply >"$WORK/dd5.log" 2>&1 || { cat "$WORK/dd5.log"; echo "FAIL exact apply"; exit 1; }
expect "$WORK/dd5.log" 'Hulu|hulu.com \(exact@x.com\): kept one, trashed 1' "exact apply reports its group"
[ "$(live '^e1')" = "1" ] && [ "$(vault e1a .deletedDate)" != "null" ] && [ "$(vault e1b .deletedDate)" = "null" ] || { echo "FAIL exact stage did not keep the newest and trash the other"; exit 1; }
[ "$(live '^b3')" = "1" ] && [ "$(vault b3a .deletedDate)" = "null" ] && [ "$(vault b3b .deletedDate)" != "null" ] || { echo "FAIL the exact stage must keep the copy that holds the passkey, even when it is the older one"; exit 1; }
[ "$(live '^(m|c|f|l|g|h|b[124-8]|p|u|n)')" = "$LEFT_BEFORE" ] || { echo "FAIL the exact stage touched a merge or blocked group"; exit 1; }
! grep -qE '^edit ' "$BWLOG" || { echo "FAIL the exact stage edited an item"; exit 1; }
pass "exact stage trashes only the identical copy, keeps the passkey holder, and touches nothing else"

dedupe "$WORK/tty-yes" merge --apply --limit 1 >"$WORK/dd6.log" 2>&1 || { cat "$WORK/dd6.log"; echo "FAIL merge apply limit 1"; exit 1; }
[ "$(live '^c1')" = "1" ] && [ "$(live '^(m1|m2)')" = "4" ] || { echo "FAIL --limit 1 did not stop after the first group"; exit 1; }
pass "--limit 1 acts on one group only"

dedupe "$WORK/tty-yes" merge --apply >"$WORK/dd7.log" 2>&1 || { cat "$WORK/dd7.log"; echo "FAIL merge apply"; exit 1; }
[ "$(vault m1b '.login.uris | length')" = "3" ] || { echo "FAIL merge did not add the other copy's URL once"; exit 1; }
[ "$(vault m1b '.notes | contains("other note") and contains("keep note")')" = "true" ] || { echo "FAIL merge dropped a note"; exit 1; }
[ "$(vault m1b '.fields | length')" = "1" ] && [ "$(vault m1b .login.totp)" = "otpauth://totp/etsy?secret=AAAA" ] || { echo "FAIL merge lost a field or the one-time-code seed"; exit 1; }
[ "$(vault m1b .favorite)" = "true" ] && [ "$(vault m1b .login.password)" = "PW-secret-merge" ] || { echo "FAIL merge lost the favorite flag or changed the password"; exit 1; }
[ "$(vault m1a .deletedDate)" != "null" ] && [ "$(vault m2a .deletedDate)" != "null" ] && [ "$(vault m2b .deletedDate)" = "null" ] || { echo "FAIL merge did not trash the other copies"; exit 1; }
[ "$(vault g1b '.login.uris | length')" = "3" ] && [ "$(vault g1b '.login.uris[2].uri')" = "zy-scheme.example.com:8443" ] && [ "$(vault g1a .deletedDate)" != "null" ] && [ "$(live '^g1')" = "1" ] || { echo "FAIL URLs on the same site with default matching (any scheme, www., path, query string) must count as one, but the same host on another port is a different URL"; exit 1; }
[ "$(vault h1b '.login.uris | length')" = "5" ] && [ "$(vault h1a .deletedDate)" != "null" ] || { echo "FAIL URLs with an exact-match setting must be compared by scheme, path and query string, ignoring only a trailing slash"; exit 1; }
[ "$(grep -c '^edit item' "$BWLOG")" = "5" ] && ! grep -qE '^edit item (e1|c1|f1|m2|b[1-8]|p[23])' "$BWLOG" || { grep '^edit' "$BWLOG"; echo "FAIL only the Etsy, Linked, Passkey-only, Scheme (port) and Exact-match keepers needed an edit"; exit 1; }
[ "$(grep -c '^get item' "$BWLOG")" = "5" ] || { grep -c '^get item' "$BWLOG"; echo "FAIL every edit must be read back from the vault"; exit 1; }
[ "$(live '^b7')" = "2" ] || { echo "FAIL a copy holding password history the kept copy lacks was trashed (bw edit cannot save a joined history)"; exit 1; }
[ "$(vault p1a .login.password)" = "PW-secret-p1" ] && [ "$(vault p1a '.login.fido2Credentials[0].credentialId')" = "cred-p1" ] && [ "$(vault p1a '.login.fido2Credentials[0].keyValue')" = "KEYDATA-p1" ] || { echo "FAIL the passkey copy did not take the password, or its passkey changed"; exit 1; }
[ "$(vault p1b .deletedDate)" != "null" ] && [ "$(vault p1a .deletedDate)" = "null" ] || { echo "FAIL the password-only copy was not trashed and the passkey copy kept"; exit 1; }
[ "$(vault l1a .deletedDate)" != "null" ] && [ "$(vault l1b '.fields | length')" = "2" ] || { echo "FAIL linked fields that differ only by linkedId were treated as identical or one was lost"; exit 1; }
[ "$(vault m1b .reprompt)" = "1" ] || { echo "FAIL merge did not keep the stricter reprompt setting"; exit 1; }
[ "$(vault f1a .deletedDate)" != "null" ] && [ "$(vault f1b .deletedDate)" = "null" ] && [ "$(vault f1b .folderId)" = "fB" ] || { echo "FAIL a copy that differs only by folder was not merged into the kept folder"; exit 1; }
pass "merge adds URLs, notes, fields and the seed to the keeper, then trashes the copy"

[ "$(live '^(b1|b2|b4|b5|b6|b7|b8|p2|p3)')" = "18" ] && [ "$(live '^(u1|u3|n1)$')" = "3" ] || { echo "FAIL a left-alone group or an unrelated item changed"; exit 1; }
! grep -q 'PW-secret' "$BWLOG" || { echo "FAIL a password reached bw's command line"; exit 1; }
! grep -q -- '--permanent' "$BWLOG" || { echo "FAIL a delete was permanent"; exit 1; }
dedupe "$WORK/tty-no" merge >"$WORK/dd8.log" 2>&1 && dedupe "$WORK/tty-no" exact >"$WORK/dd9.log" 2>&1 || { echo "FAIL final dry runs"; exit 1; }
expect "$WORK/dd8.log" '^0 group\(s\) to change, 9 left alone, 0 for another stage' "a second merge run finds nothing left to do"
expect "$WORK/dd9.log" '^0 group\(s\) to change, 9 left alone, 0 for another stage' "a second exact run finds nothing left to do"
pass "left-alone groups stay; no password on a command line; deletes go to the trash"

# After each edit the item is read back. If bw saved something other than what was meant (a dropped
# passkey, a blanked password) the run stops before that group's other copies are trashed.
for spec in "drop-passkey:p1:passkey" "rewrite-rpid:p1:passkey" "blank-password:p1:password" "drop-fields:l1:custom fields" "rename:m1:name" "unfavorite:m1:favorite"; do
  bug="${spec%%:*}"; rest="${spec#*:}"; group="${rest%%:*}"; what="${rest#*:}"
  /usr/bin/jq --arg g "^$group" '[.[] | select(.id | test($g))]' "$FX/dupes.json" >"$WORK/state-$bug.json"
  DELETES_BEFORE="$(grep -c '^delete' "$BWLOG")"
  if ( STATE="$WORK/state-$bug.json"; FAKE_BW_EDIT_BUG="$bug" dedupe "$WORK/tty-yes" merge --apply >"$WORK/dd-$bug.log" 2>&1 ); then
    cat "$WORK/dd-$bug.log"; echo "FAIL the run went on after bw saved a bad edit ($bug)"; exit 1
  fi
  [ "$(grep -c '^delete' "$BWLOG")" = "$DELETES_BEFORE" ] || { echo "FAIL a copy was trashed after a bad edit ($bug)"; exit 1; }
  expect "$WORK/dd-$bug.log" "bw saved a different .*$what" "a bad edit ($bug) is caught after the edit"
  ! grep -q 'PW-secret\|KEYDATA' "$WORK/dd-$bug.log" || { echo "FAIL a secret reached the verification message ($bug)"; exit 1; }
done
expect "$WORK/dd-drop-passkey.log" 'may already be changed' "the stop says the passkey itself may already be changed, not only that nothing was trashed"
pass "a bad edit stops the run before anything is trashed, and the message holds no secret"

# An id that starts with "-" could be read by bw as an option, so apply refuses before any call.
/usr/bin/jq '[.[] | select(.id | test("^e1"))] | map(.id |= "-" + .)' "$FX/dupes.json" >"$WORK/state-dash.json"
DELETES_BEFORE="$(grep -c '^delete' "$BWLOG")"
if ( STATE="$WORK/state-dash.json"; dedupe "$WORK/tty-yes" exact --apply >"$WORK/dd10.log" 2>&1 ); then cat "$WORK/dd10.log"; echo "FAIL an id starting with a dash was acted on"; exit 1; fi
expect "$WORK/dd10.log" "id starts with '-'" "apply refuses an id that bw could read as an option"
[ "$(grep -c '^delete' "$BWLOG")" = "$DELETES_BEFORE" ] || { echo "FAIL a delete ran before the dash id was refused"; exit 1; }
pass "an option-like item id is refused before any bw call"

# If bw never reports organizationId, shared items cannot be told apart, so nothing may run.
/usr/bin/jq 'map(del(.organizationId))' "$FX/dupes.json" >"$WORK/state-noorg.json"
if ( STATE="$WORK/state-noorg.json"; dedupe "$WORK/tty-no" exact >"$WORK/dd11.log" 2>&1 ); then cat "$WORK/dd11.log"; echo "FAIL ran without any organizationId in the vault"; exit 1; fi
expect "$WORK/dd11.log" 'belong to an organization' "a vault that never reports organizations is refused"
pass "no organization information means no dedupe"

# --- dedupe pick: groups whose only conflict is different passwords ----------------------------------
# Bank one (b1): b1a's password changed most recently, though b1b was edited later and is the kept copy.
# k1: the passkey copy holds the older password. s1: skipped with Enter. w1: the kept copy's own password
# is picked, so no edit. x1 (seeds), y1 (a field), y2 (history) and y3 (a match setting) also differ by
# password and stay left alone, as does b4 (seeds only). Zoom (m2) is for the merge stage. Cannot catch the real
# bw reporting passwordRevisionDate differently from this model.
expect "$WORK/dd2.log" 'different passwords: dedupe pick' "exact and merge point to the pick stage for different-password groups"
/usr/bin/jq '[.[] | select(.id | test("^(b1|b4|m2)"))] | map(if .id == "b1a" then .creationDate = "2025-12-01T00:00:00Z" elif .id == "b1b" then .creationDate = "2024-01-01T00:00:00Z" | .login.passwordRevisionDate = "2025-06-01T00:00:00Z" | .passwordHistory = [{"lastUsedDate":"2025-06-01T00:00:00Z","password":"PW-secret-b1-older"}] else . end) + [
  {"id":"k1a","type":1,"organizationId":null,"name":"Kay","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2025-01-01T00:00:00Z","revisionDate":"2025-06-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"k@x.com","password":"PW-secret-k1-old","passwordRevisionDate":null,"totp":null,"fido2Credentials":[{"credentialId":"cred-k1","keyValue":"KEYDATA-k1","rpId":"k1.example.com"}],"uris":[{"match":null,"uri":"https://k1.example.com"}]}},
  {"id":"k1b","type":1,"organizationId":null,"name":"Kay","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2026-04-01T09:30:00Z","revisionDate":"2026-04-02T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"k@x.com","password":"PW-secret-k1-new","passwordRevisionDate":null,"totp":null,"uris":[{"match":null,"uri":"https://k1.example.com"},{"match":null,"uri":"https://login.k1.example.com"}]}},
  {"id":"s1a","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":"fA","favorite":false,"reprompt":0,"creationDate":"2025-06-01T00:00:00Z","revisionDate":"2026-01-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"s@x.com","password":"PW-secret-s1-a","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"s1b","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2024-01-01T00:00:00Z","revisionDate":"2026-02-01T00:00:00Z","deletedDate":null,"fields":[],"passwordHistory":[{"lastUsedDate":"2026-01-15T00:00:00Z","password":"PW-secret-s1-older"}],"login":{"username":"s@x.com","password":"PW-secret-s1-b","passwordRevisionDate":"2026-01-15T00:00:00Z","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"s1c","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2025-01-01T00:00:00Z","revisionDate":"2025-12-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"s@x.com","password":"","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"y1a","type":1,"organizationId":null,"name":"Field clash","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","fields":[{"name":"pin","value":"1111","type":0}],"deletedDate":null,"login":{"username":"y1@x.com","password":"PW-secret-y1-a","totp":null,"uris":[{"match":null,"uri":"https://y1.example.com"}]}},
  {"id":"y1b","type":1,"organizationId":null,"name":"Field clash","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","fields":[{"name":"pin","value":"2222","type":0}],"deletedDate":null,"login":{"username":"y1@x.com","password":"PW-secret-y1-b","totp":null,"uris":[{"match":null,"uri":"https://y1.example.com"}]}},
  {"id":"y2a","type":1,"organizationId":null,"name":"History gap","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","fields":[],"passwordHistory":[{"lastUsedDate":"2025-01-01T00:00:00Z","password":"PW-secret-y2-older"}],"deletedDate":null,"login":{"username":"y2@x.com","password":"PW-secret-y2-a","totp":null,"uris":[{"match":null,"uri":"https://y2.example.com"}]}},
  {"id":"y2b","type":1,"organizationId":null,"name":"History gap","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","fields":[],"deletedDate":null,"login":{"username":"y2@x.com","password":"PW-secret-y2-b","totp":null,"uris":[{"match":null,"uri":"https://y2.example.com"}]}},
  {"id":"y3a","type":1,"organizationId":null,"name":"Match clash","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","fields":[],"deletedDate":null,"login":{"username":"y3@x.com","password":"PW-secret-y3-a","totp":null,"uris":[{"match":null,"uri":"https://y3.example.com"}]}},
  {"id":"y3b","type":1,"organizationId":null,"name":"Match clash","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","fields":[],"deletedDate":null,"login":{"username":"y3@x.com","password":"PW-secret-y3-b","totp":null,"uris":[{"match":3,"uri":"https://y3.example.com"}]}},
  {"id":"w1a","type":1,"organizationId":null,"name":"Own pick","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2025-01-01T00:00:00Z","revisionDate":"2026-01-01T00:00:00Z","fields":[],"deletedDate":null,"login":{"username":"w@x.com","password":"PW-secret-w1-a","totp":null,"uris":[{"match":null,"uri":"https://w1.example.com"}]}},
  {"id":"w1b","type":1,"organizationId":null,"name":"Own pick","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2026-03-01T00:00:00Z","revisionDate":"2026-03-01T00:00:00Z","fields":[],"deletedDate":null,"login":{"username":"w@x.com","password":"PW-secret-w1-b","totp":null,"uris":[{"match":null,"uri":"https://w1.example.com"}]}},
  {"id":"x1a","type":1,"organizationId":null,"name":"Both","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"x@x.com","password":"PW-secret-x1-a","totp":"otpauth://totp/x?secret=AAAA","uris":[{"match":null,"uri":"https://x1.example.com"}]}},
  {"id":"x1b","type":1,"organizationId":null,"name":"Both","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"x@x.com","password":"PW-secret-x1-b","totp":"otpauth://totp/x?secret=BBBB","uris":[{"match":null,"uri":"https://x1.example.com"}]}}]' "$FX/dupes.json" >"$WORK/state-pick.json"
cp "$WORK/state-pick.json" "$WORK/state-pick-before.json"
pick() { # pick <tty file> <log> <args...>
  local tty="$1" log="$2"; shift 2
  ( STATE="$WORK/state-pick.json"; BWLOG="$WORK/bw-pick.log"; export TZ="${PICK_TZ:-UTC}"; dedupe "$tty" pick "$@" >"$log" 2>&1 )
}
: >"$WORK/bw-pick.log"
pick "$WORK/tty-no" "$WORK/pk1.log" || { cat "$WORK/pk1.log"; echo "FAIL pick dry run"; exit 1; }
expect "$WORK/pk1.log" '^4 group\(s\) to change, 5 left alone, 1 for another stage' "pick counts only groups whose sole conflict is the password"
for why in '2 different one-time-code seeds' '1 a custom field with different values' '1 a copy has password history the kept copy lacks' '1 the same URL with different match settings'; do
  expect "$WORK/pk1.log" "Left alone:.*$why" "different passwords plus another conflict stays left alone with that reason: $why"
done
expect "$WORK/pk1.log" '^ +1 +"Bank one" +folder: no folder +edited 2026-01-01 00:00, created 2025-12-01 00:00$' "a copy created after the other's last password change is listed first, dates in local time"
expect "$WORK/pk1.log" '^ +2 +"Bank one" +folder: no folder +password changed 2025-06-01 00:00, edited 2026-02-01 00:00, created 2024-01-01 00:00 +\(kept entry\)$' "an older password change ranks second though edited later; every date bw reports is shown"
expect "$WORK/pk1.log" '^ +1 +"Kay" .*edited 2026-04-02 00:00, created 2026-04-01 09:30$' "a never-changed password ranks by its copy's creation date"
expect "$WORK/pk1.log" '^ +1 +"Odd folder" +folder: no folder +password changed 2026-01-15 00:00.*\(kept entry\)$' "a recent password change ranks above copies created earlier"
expect "$PLANS/plan-pick.md" '^\| k1.example.com \(k@x.com\) \| 2 \|.*\| the password you choose; \+1 URL' "the pick plan says what the kept copy gains besides the password"
expect "$WORK/pk1.log" '^ +2 +"Kay" .*\(kept entry, holds a passkey\)$' "the passkey copy is the kept entry even with the older password"
expect "$WORK/pk1.log" 'Nothing was changed' "a pick dry run changes nothing"
cmp -s "$WORK/state-pick.json" "$WORK/state-pick-before.json" && ! grep -qE '^(edit|delete) ' "$WORK/bw-pick.log" || { echo "FAIL a pick dry run changed the vault"; exit 1; }
PICK_TZ=America/New_York pick "$WORK/tty-no" "$WORK/pk5.log" || { cat "$WORK/pk5.log"; echo "FAIL pick dry run in New York time"; exit 1; }
expect "$WORK/pk5.log" '^ +1 +"Bank one" +folder: no folder +edited 2025-12-31 19:00, created 2025-11-30 19:00$' "dates are shown in the person's own time zone"

printf '9\n\n3\n\n' >"$WORK/tty-skip"
pick "$WORK/tty-skip" "$WORK/pk2.log" --apply || { cat "$WORK/pk2.log"; echo "FAIL skipping every group must end cleanly"; exit 1; }
expect "$WORK/pk2.log" 'not one of the numbers shown, so this group is skipped' "an answer that is not a listed number skips the group"
expect "$WORK/pk2.log" 'That copy has no password, so this group is skipped' "choosing a copy with no password skips the group instead of blanking the password"
expect "$WORK/pk2.log" 'No group was chosen. Nothing was changed.' "skipping every group changes nothing"
! grep -q 'Type DEDUPE' "$WORK/pk2.log" || { echo "FAIL the confirmation was asked with nothing chosen"; exit 1; }
printf '0\n3\n\n' >"$WORK/tty-edges"
pick "$WORK/tty-edges" "$WORK/pk2b.log" --apply || { cat "$WORK/pk2b.log"; echo "FAIL edge answers must end cleanly"; exit 1; }
[ "$(grep -o 'not one of the numbers shown' "$WORK/pk2b.log" | wc -l | tr -d ' ')" = "2" ] || { cat "$WORK/pk2b.log"; echo "FAIL 0, and one past the last copy, must each be refused"; exit 1; }
expect "$WORK/pk2b.log" 'or press Enter to skip: Skipped\.$' "Enter skips with its own message"
printf '\n' >"$WORK/tty-enter"
pick "$WORK/tty-enter" "$WORK/pk6.log" --apply --limit 1 || { cat "$WORK/pk6.log"; echo "FAIL pick apply 1"; exit 1; }
[ "$(grep -o 'press Enter to skip: ' "$WORK/pk6.log" | wc -l | tr -d ' ')" = "1" ] || { echo "FAIL apply 1 must ask about one group only"; exit 1; }
printf '1\n1\n\n1\nno\n' >"$WORK/tty-pick-no"
if pick "$WORK/tty-pick-no" "$WORK/pk3.log" --apply; then echo "FAIL pick went ahead without the confirmation word"; exit 1; fi
expect "$WORK/pk3.log" 'This will edit 2 kept copies and move 3 copies to the Bitwarden trash' "pick states the edits and the trashing before the confirmation"
cmp -s "$WORK/state-pick.json" "$WORK/state-pick-before.json" && ! grep -qE '^(edit|delete) ' "$WORK/bw-pick.log" || { echo "FAIL an unconfirmed pick changed the vault"; exit 1; }
pass "pick ranks by password date, previews, and changes nothing until a group is chosen and DEDUPE typed"

printf '1\n1\n\n1\nDEDUPE\n' >"$WORK/tty-pick"
pick "$WORK/tty-pick" "$WORK/pk4.log" --apply || { cat "$WORK/pk4.log"; echo "FAIL pick apply"; exit 1; }
pv() { /usr/bin/jq -r --arg id "$1" ".[] | select(.id == \$id) | $2" "$WORK/state-pick.json"; }
[ "$(pv b1b .login.password)" = "PW-secret-b1-old" ] && [ "$(pv b1a .deletedDate)" != "null" ] && [ "$(pv b1b .deletedDate)" = "null" ] || { echo "FAIL the chosen password was not saved on the kept copy, or the other copy not trashed"; exit 1; }
[ "$(pv k1a .login.password)" = "PW-secret-k1-new" ] && [ "$(pv k1a '.login.fido2Credentials[0].keyValue')" = "KEYDATA-k1" ] && [ "$(pv k1b .deletedDate)" != "null" ] || { echo "FAIL the passkey copy must keep its passkey and take the chosen password"; exit 1; }
[ "$(pv s1a .deletedDate)" = "null" ] && [ "$(pv s1b .deletedDate)" = "null" ] && [ "$(pv s1a .login.password)" = "PW-secret-s1-a" ] || { echo "FAIL a skipped group was changed"; exit 1; }
[ "$(/usr/bin/jq '[.[] | select(.id | test("^(x1|y|b4|m2)")) | select(.deletedDate == null)] | length' "$WORK/state-pick.json")" = "12" ] && ! grep -qE '^(edit|delete) item (x1|y|b4|m2|s1)' "$WORK/bw-pick.log" || { echo "FAIL pick touched a group it does not act on"; exit 1; }
[ "$(pv w1b .login.password)" = "PW-secret-w1-b" ] && [ "$(pv w1a .deletedDate)" != "null" ] && ! grep -q '^edit item w1' "$WORK/bw-pick.log" || { echo "FAIL picking the kept copy's own password must trash the rest without an edit"; exit 1; }
[ "$(grep -c '^get item' "$WORK/bw-pick.log")" = "2" ] || { echo "FAIL every pick edit must be read back"; exit 1; }
! grep -q 'PW-secret\|KEYDATA' "$WORK/pk1.log" "$WORK/pk2.log" "$WORK/pk3.log" "$WORK/pk4.log" "$WORK/pk5.log" "$WORK/pk2b.log" "$WORK/pk6.log" "$PLANS/plan-pick.md" || { echo "FAIL a password or passkey key reached the terminal or the plan"; exit 1; }
pass "pick saves the chosen password on the kept copy, keeps a passkey, trashes the rest, and leaves skipped groups alone"

# The entry point refuses a bad dedupe request before it asks for a master password. Cannot catch
# a valid request misbehaving after sign-in; that needs a real vault.
for bad in "bogus" "exact later" "exact 5" "exact apply 1 extra" "exact apply abc" "merge apply 0"; do
  # shellcheck disable=SC2086
  if HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash bw-health.sh dedupe $bad >"$WORK/dd-arg.log" 2>&1; then
    cat "$WORK/dd-arg.log"; echo "FAIL 'dedupe $bad' was accepted"; exit 1
  fi
  ! grep -q 'master password' "$WORK/dd-arg.log" || { echo "FAIL 'dedupe $bad' reached sign-in"; exit 1; }
done
expect "$WORK/dd-arg.log" 'a limit goes after apply' "a bad limit is explained"
pass "bad dedupe requests are refused before sign-in"

# A mistyped master password gets a plain explanation, not only Bitwarden's developer error lines. Cannot catch
# the real bw's wording or exit status; only that a failing unlock or login is explained in plain words.
PW_HOME="$WORK/pw-home"
mkdir -p "$PW_HOME/.local/bin" "$PW_HOME/Desktop" "$PW_HOME/Library/Application Support/bw-health/bin"
ln -s "$FAKE_HOME/.local/bin/uv" "$PW_HOME/.local/bin/uv"
cat >"$PW_HOME/Library/Application Support/bw-health/bin/bw" <<'EOF'
#!/bin/bash
case "$1" in
  status) echo "{\"status\":\"$FAKE_BW_STATUS\"}" ;;
  unlock) echo "ERROR bitwarden_crypto::keys::master_key: error=The decryption operation failed" >&2; exit 1 ;;
  login) echo "Username or password is incorrect. Try again." >&2; exit 1 ;;
esac
EOF
chmod +x "$PW_HOME/Library/Application Support/bw-health/bin/bw"
printf 'x\n' >"$WORK/tty-pw"
for state in locked unauthenticated; do
  if HOME="$PW_HOME" BW_HEALTH_BASE_URL="file://$ROOT" BW_HEALTH_TTY="$WORK/tty-pw" FAKE_BW_STATUS="$state" /bin/bash bw-health.sh >"$WORK/pw-$state.log" 2>&1; then
    cat "$WORK/pw-$state.log"; echo "FAIL a failed sign-in ($state) exited successfully"; exit 1
  fi
  ! grep -q 'Send a screenshot' "$WORK/pw-$state.log" || { cat "$WORK/pw-$state.log"; echo "FAIL a mistyped password must not be told to send a screenshot ($state)"; exit 1; }
  expect "$WORK/pw-$state.log" 'Nothing in your vault was changed' "a failed sign-in ($state) says nothing was changed"
  expect "$WORK/pw-$state.log" 'Caps Lock' "a failed sign-in ($state) names the usual cause"
done
expect "$WORK/pw-locked.log" 'did not unlock your Bitwarden vault' "a failed unlock says so in plain words"
expect "$WORK/pw-locked.log" 'decryption operation failed' "the developer error is still shown, for whoever helps"
expect "$WORK/pw-locked.log" 'stop after two tries' "a failed unlock tells people when to stop"
expect "$WORK/pw-unauthenticated.log" 'Sign-in did not complete' "a failed first sign-in says so in plain words"
pass "a failed sign-in or unlock is explained in plain words"
if HOME="$PW_HOME" BW_HEALTH_BASE_URL="file://$ROOT" BW_HEALTH_TTY="$WORK/tty-pw" FAKE_BW_STATUS=locked /bin/bash bw-health.sh dedupe pick apply 2 >"$WORK/pw-pick.log" 2>&1; then
  echo "FAIL the locked stand-in vault unlocked"; exit 1
fi
expect "$WORK/pw-pick.log" 'did not unlock your Bitwarden vault' "the entry point accepts 'dedupe pick apply 2' and goes on to sign-in"

# --- a bad request is refused before anything is installed, fetched or asked ------------------------
EMPTY_HOME="$WORK/empty-home"; mkdir "$EMPTY_HOME"
refuse() { # refuse <regex> <args...>
  local want="$1"; shift
  if HOME="$EMPTY_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash bw-health.sh "$@" >"$WORK/refuse.log" 2>&1; then
    cat "$WORK/refuse.log"; echo "FAIL '$*' was accepted"; exit 1
  fi
  grep -qE -e "$want" "$WORK/refuse.log" || { cat "$WORK/refuse.log"; echo "FAIL '$*' was refused without saying: $want"; exit 1; }
  [ -z "$(ls -A "$EMPTY_HOME")" ] || { echo "FAIL '$*' was refused only after something was written to the home folder"; exit 1; }
}
for bad in Mom 'mom dad' ../mom -mom '' mom_1 --logout-after; do refuse 'a --user name is 1 to 32 lowercase' --user "$bad"; done
refuse 'a --user name is 1 to 32 lowercase' --user abcdefghijklmnopqrstuvwxyz0123456
refuse '--user needs a name after it' check --user
refuse '--user was given twice' --user mom --user dad
refuse 'unknown option: --usr' --usr mom
refuse 'unknown step: logut' --user mom logut
refuse 'nothing is allowed after logout' --user mom logout now
refuse '--logout-after goes with a run that signs in, not with check' check --logout-after
refuse '--logout-after goes with a run that signs in, not with logout' --user mom logout --logout-after
pass "a bad profile name, option or step is refused before anything is installed"

# --- where the report scripts come from --------------------------------------------------------------
# A copy of the checkout with a marked script. Run as a file with no BW_HEALTH_BASE_URL it must use the
# files beside it, and only once the marked file's checksum is written in the copy's own entry script.
# Cannot catch the published copies being fetched as well and then overwritten.
# shellcheck disable=SC2086
mkdir "$WORK/clone" "$WORK/clone2"; cp bw-health.sh $FILES "$WORK/clone/"; cp bw-health.sh $FILES "$WORK/clone2/"
echo '# marked local copy' >>"$WORK/clone/bw_report.py"
if env -u BW_HEALTH_BASE_URL HOME="$FAKE_HOME" /bin/bash "$WORK/clone/bw-health.sh" check >"$WORK/local0.log" 2>&1; then echo "FAIL a changed local script was used without its checksum"; exit 1; fi
expect "$WORK/local0.log" 'bw_report.py did not match the checksum written in bw-health.sh, so it was not used. If you changed it, update its checksum' "a changed script beside the file is refused until its checksum is updated"
sed -i '' "s/$(shasum -a 256 bw_report.py | cut -d' ' -f1)/$(shasum -a 256 "$WORK/clone/bw_report.py" | cut -d' ' -f1)/" "$WORK/clone/bw-health.sh"
env -u BW_HEALTH_BASE_URL HOME="$FAKE_HOME" /bin/bash "$WORK/clone/bw-health.sh" check >"$WORK/local.log" 2>&1 || { cat "$WORK/local.log"; echo "FAIL check from a checkout"; exit 1; }
expect "$WORK/local.log" "^==> bw-health v$VERSION, using the report scripts beside this file" "a run from a checkout says it uses its own scripts"
! grep -q 'curl -fsSL' "$WORK/local.log" || { echo "FAIL a run from a checkout showed the paste line as if it were the release"; exit 1; }
cmp -s "$WORK/clone/bw_report.py" "$APP/bw_report.py" || { echo "FAIL a run from a checkout did not use the script beside it"; exit 1; }
# The unmarked copy, pointed at the marked one: it must fetch from there (and so refuse it), not use its own files.
if HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$WORK/clone" /bin/bash "$WORK/clone2/bw-health.sh" check >"$WORK/local2.log" 2>&1; then echo "FAIL BW_HEALTH_BASE_URL did not win over the files beside the script"; exit 1; fi
expect "$WORK/local2.log" 'Fetching the report scripts' "BW_HEALTH_BASE_URL still wins over the files beside the script"
expect "$WORK/local2.log" 'bw_report.py did not match the checksum' "and what it serves is checked like any other source"
rm "$WORK/clone/bw_dedupe.py"
if env -u BW_HEALTH_BASE_URL HOME="$FAKE_HOME" /bin/bash "$WORK/clone/bw-health.sh" check >"$WORK/local3.log" 2>&1; then echo "FAIL a checkout missing a script was accepted"; exit 1; fi
expect "$WORK/local3.log" "only some of this tool's files are beside bw-health.sh" "a checkout missing one file is refused, not topped up from the published ones"
HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$ROOT" /bin/bash -s -- --user mom check <bw-health.sh >"$WORK/piped.log" 2>&1 || { cat "$WORK/piped.log"; echo "FAIL piped check with --user"; exit 1; }
expect "$WORK/piped.log" 'Installed OK' "--user works on the paste line (bash -s -- --user NAME)"
[ -d "$APP/profiles/mom/data" ] || { echo "FAIL a piped --user run did not use the profile's folder"; exit 1; }
pass "a checkout runs its own files; the paste line and BW_HEALTH_BASE_URL fetch them; every source is checksummed"

# --- several people on one Mac account: --user NAME ---------------------------------------------------
# A stand-in bw that keeps its sign-in in the data folder it is pointed at, as the real one does, and
# serves a different vault per account. `open` is a stand-in too, so no browser or Finder window opens.
# Cannot catch the real bw signing in, locking or signing out differently from this model.
MU_HOME="$WORK/mu-home"; MU_APP="$MU_HOME/Library/Application Support/bw-health"; MU_DL="$MU_HOME/Downloads"
MOM="$MU_APP/profiles/mom"; DAD="$MU_APP/profiles/dad"; MU_BWLOG="$WORK/mu-bw.log"; MU_OPENLOG="$WORK/mu-open.log"
mkdir -p "$MU_HOME/.local/bin" "$MU_HOME/Desktop" "$MU_DL" "$MU_APP/bin" "$WORK/mu-bin" "$WORK/vaults"
ln -s "$FAKE_HOME/.local/bin/uv" "$MU_HOME/.local/bin/uv"
cat >"$MU_APP/bin/bw" <<'EOF'
#!/bin/bash
D="$BITWARDENCLI_APPDATA_DIR"
echo "${D#*/bw-health/} $*" >>"$FAKE_BW_LOG"
case "$1" in
  status)
    if [ -f "$D/account" ]; then
      state=locked; [ -z "${BW_SESSION:-}" ] || state=unlocked
      echo "{\"status\":\"$state\",\"userEmail\":\"$(cat "$D/account")\"}"
    else
      echo '{"status":"unauthenticated","userEmail":null}'
    fi ;;
  login)
    [ ! -f "$D/account" ] || { echo "You are already logged in." >&2; exit 1; }
    echo "$FAKE_BW_EMAIL" >"$D/account"; echo "session-key" ;;
  unlock) [ -f "$D/account" ] || { echo "You are not logged in." >&2; exit 1; }; echo "session-key" ;;
  lock) ;;
  logout)
    [ -f "$D/account" ] || { echo "You are not logged in." >&2; exit 1; }
    case "${FAKE_BW_LOGOUT_BUG:-}" in
      fails) echo "Logout failed." >&2; exit 1 ;;
      silent) ;;
      *) rm "$D/account" ;;
    esac ;;
  sync) echo 'Syncing complete.' ;;
  list)
    case "$#:$2" in
      2:items) cat "$FAKE_BW_VAULTS/$(cat "$D/account").json" ;;
      2:folders) cat "$FAKE_BW_FOLDERS" ;;
      *) echo "Invalid command: $*" >&2; exit 1 ;;
    esac ;;
  *) echo "Invalid command: $*" >&2; exit 1 ;;
esac
EOF
printf '#!/bin/bash\necho "$*" >>"$FAKE_OPEN_LOG"\n' >"$WORK/mu-bin/open"
chmod +x "$MU_APP/bin/bw" "$WORK/mu-bin/open"
cp "$FX/items.json" "$WORK/vaults/mom@example.com.json"
cp "$FX/items.json" "$WORK/vaults/owner@example.com.json"
cp "$FX/dupes.json" "$WORK/vaults/kelly@example.com.json"
echo '[{"id":"d1","type":1,"name":"Dad bank","deletedDate":null,"login":{"username":"dad","password":"Vt6#qLp9$wZ3mK8x!r","uris":[{"uri":"https://dadbank.example.com"}]}}]' >"$WORK/vaults/dad@example.com.json"
UV_CACHE="$(uv cache dir)"; UV_PYTHONS="$(uv python dir)"  # the stand-in home must not download Python again
: >"$MU_BWLOG"; : >"$MU_OPENLOG"
mu() { # mu <account email> <tty file> <args...>: one run from this checkout, with its own scripts
  local email="$1" tty="$2"; shift 2
  env -u BW_SESSION -u BW_HEALTH_BASE_URL HOME="$MU_HOME" PATH="$WORK/mu-bin:$PATH" UV_CACHE_DIR="$UV_CACHE" UV_PYTHON_INSTALL_DIR="$UV_PYTHONS" \
    BW_HEALTH_TTY="$tty" FAKE_BW_EMAIL="$email" FAKE_BW_LOG="$MU_BWLOG" FAKE_BW_VAULTS="$WORK/vaults" FAKE_BW_FOLDERS="$FX/folders.json" \
    FAKE_OPEN_LOG="$MU_OPENLOG" /bin/bash bw-health.sh "$@"
}
snapshot() { ( cd "$1" && find . -type f -exec shasum {} + | sort ); } # every file under a folder, with its hash
newest_report() { ls "$1/Reports"/*.html | tail -1; }                   # <a person's bw-health folder>
bw_calls_since() { tail -n "+$(($1 + 1))" "$MU_BWLOG"; }                # <line count before a run>

# Both people's exports are in Downloads at once: the case that used to mix one into the other's vault.
cp "$FX/chrome.csv" "$MU_DL/Google Passwords.csv"
cp "$FX/apple.csv" "$MU_DL/Passwords.csv"; touch -t "$(date -v-1H +%Y%m%d%H%M)" "$MU_DL/Passwords.csv"
cp "$FX/chrome2.csv" "$MU_DL/Old Passwords.csv"; touch -t "$(date -v-10d +%Y%m%d%H%M)" "$MU_DL/Old Passwords.csv"
printf 'url,title\nhttps://x.com,not a password file\n' >"$MU_DL/other.csv"

# mom, first run: sign in, report, then the list of exports. Three answers that are refused, then file 1.
printf '4\n1 1\nhunter2\n1\n' >"$WORK/tty-mom"
mu mom@example.com "$WORK/tty-mom" --user mom >"$WORK/mu1.log" 2>&1 || { cat "$WORK/mu1.log"; echo "FAIL mom's first run"; exit 1; }
expect "$WORK/mu1.log" 'using the report scripts beside this file' "a profile run from a checkout uses its own scripts"
expect "$WORK/mu1.log" "Profile mom: sign in to Bitwarden. Type mom's email" "a new profile is asked to sign in"
expect "$WORK/mu1.log" 'Profile mom: this run uses the vault of mom@example.com' "the run says whose vault the profile holds"
grep -qx 'profiles/mom/data login --raw' "$MU_BWLOG" || { cat "$MU_BWLOG"; echo "FAIL mom did not sign in to her own data folder"; exit 1; }
expect "$WORK/mu1.log" '^  1  Google Passwords.csv  \(chrome, saved [0-9-]+ [0-9:]+\)$' "the newest export is listed first, with its kind and time"
expect "$WORK/mu1.log" '^  2  Passwords.csv  \(apple, saved [0-9-]+ [0-9:]+\)$' "the second export is listed"
expect "$WORK/mu1.log" '^  3  Old Passwords.csv  \(chrome, saved [0-9-]+ [0-9:]+, older than 7 days\)$' "an old export is listed and marked as old"
! grep -q 'other.csv' "$WORK/mu1.log" || { echo "FAIL a csv that is not a password export was listed"; exit 1; }
[ "$(grep -o 'Each answer must be one of the numbers 1 to 3, used once' "$WORK/mu1.log" | wc -l | tr -d ' ')" = "3" ] || { cat "$WORK/mu1.log"; echo "FAIL a number past the list, a repeated number and a word must each be refused and asked again"; exit 1; }
! grep -q 'hunter2' "$WORK/mu1.log" || { echo "FAIL a refused answer was printed back (it could be a password)"; exit 1; }
expect "$WORK/mu1.log" "Moved Google Passwords.csv to Bitwarden Import/chrome-passwords-$TODAY.csv" "the chosen export is moved"
expect "$WORK/mu1.log" '2 other password export file\(s\) are still in Downloads, untouched' "the run says what it left in Downloads"
[ "$(LC_ALL=C ls "$MU_DL" | tr '\n' '|')" = "Old Passwords.csv|Passwords.csv|other.csv|" ] || { ls "$MU_DL"; echo "FAIL only the chosen export may leave Downloads"; exit 1; }
[ "$(ls "$MOM/Bitwarden Import" | tr '\n' '|')" = "chrome-passwords-$TODAY.csv|conflicts.md|new-for-bitwarden.csv|" ] || { echo "FAIL mom's import folder must hold her export and its diff, nothing else"; ls "$MOM/Bitwarden Import" || true; exit 1; }
grep -q 'spotify.com' "$MOM/Bitwarden Import/new-for-bitwarden.csv" && ! grep -q 'library.org' "$MOM/Bitwarden Import/new-for-bitwarden.csv" || { echo "FAIL mom's import file must come from her export only"; exit 1; }
expect "$WORK/mu1.log" "These files are mom's. Import them only into the vault of mom@example.com" "the import step names the vault the files are for"
[ "$(ls "$MOM/Reports" | tr '\n' '|' | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{6}/STAMP/')" = "Bitwarden Report - mom STAMP.html|progress.json|" ] || { echo "FAIL mom's Reports folder must hold one dated report and the progress file"; ls "$MOM/Reports" || true; exit 1; }
expect "$(newest_report "$MOM")" '<td>Logins with a password</td><td>5</td>' "mom's report is her vault, in her own Reports folder"
expect "$(newest_report "$MOM")" '<strong>First check-up of this vault on this Mac: [0-9]+ flagged\.</strong>' "a first report says it is the first"
[ "$(stat -f %Lp "$MOM/Reports")$(stat -f %Lp "$(newest_report "$MOM")")$(stat -f %Lp "$MOM/Reports/progress.json")" = "700600600" ] || { echo "FAIL the Reports folder, the report and the progress file must be owner-only"; exit 1; }
[ "$(tail -1 "$WORK/mu1.log")" = "==> Done. The report is open in your browser. It is kept in $MOM/Reports, not on the Desktop. Your vault is locked again." ] || { tail -2 "$WORK/mu1.log"; echo "FAIL the closing line must say where the report is kept"; exit 1; }
[ ! -e "$MU_APP/data" ] && [ ! -e "$MU_APP/Bitwarden Import" ] && [ ! -e "$MU_APP/Reports" ] && [ -z "$(ls -A "$MU_HOME/Desktop")" ] || { echo "FAIL a profile run wrote to the shared sign-in, import folder or reports, or to the Desktop"; exit 1; }
[ "$(/usr/bin/jq 'type == "object" and length > 1000' "$MU_APP/2fa-directory.json")" = "true" ] || { echo "FAIL the two-step list was not kept in the shared folder"; exit 1; }
LIST_STAMP="$(stat -f '%m %i' "$MU_APP/2fa-directory.json")"
pass "a profile run signs in to its own folder and takes only the export typed for it"

# dad, straight after: his own sign-in, his own folders, and nothing of mom's is read or changed.
MOM_BEFORE="$(snapshot "$MOM")"
CALLS="$(wc -l <"$MU_BWLOG")"; : >"$MU_OPENLOG"
printf '1\n' >"$WORK/tty-dad"
mu dad@example.com "$WORK/tty-dad" --user dad >"$WORK/mu2.log" 2>&1 || { cat "$WORK/mu2.log"; echo "FAIL dad's first run"; exit 1; }
expect "$WORK/mu2.log" "Profile dad: sign in to Bitwarden" "the second person is asked to sign in, not to unlock the first person's vault"
expect "$WORK/mu2.log" 'Profile dad: this run uses the vault of dad@example.com' "the second run says it holds the second person's vault"
bw_calls_since "$CALLS" | grep -qx 'profiles/dad/data login --raw' || { echo "FAIL dad did not sign in to his own data folder"; exit 1; }
! bw_calls_since "$CALLS" | grep -qv '^profiles/dad/data ' || { bw_calls_since "$CALLS"; echo "FAIL dad's run called bw on another data folder"; exit 1; }
expect "$WORK/mu2.log" '^  1  Passwords.csv  \(apple, saved' "the export mom left is offered to dad"
[ "$(ls "$DAD/Bitwarden Import" | tr '\n' '|')" = "apple-passwords-$TODAY.csv|conflicts.md|new-for-bitwarden.csv|" ] || { echo "FAIL dad's import folder must hold his export and its diff"; ls "$DAD/Bitwarden Import" || true; exit 1; }
grep -q 'library.org' "$DAD/Bitwarden Import/new-for-bitwarden.csv" && ! grep -q 'spotify.com' "$DAD/Bitwarden Import/new-for-bitwarden.csv" || { echo "FAIL dad's import file must come from his export only"; exit 1; }
expect "$(newest_report "$DAD")" '<td>Logins with a password</td><td>1</td>' "dad's report is his vault, in his own Reports folder"
[ "$(snapshot "$MOM")" = "$MOM_BEFORE" ] || { echo "FAIL dad's run changed mom's folder, reports or progress"; exit 1; }
grep -qxF "$(newest_report "$DAD")" "$MU_OPENLOG" && grep -qxF "$DAD/Bitwarden Import" "$MU_OPENLOG" && ! grep -q 'mom' "$MU_OPENLOG" || { cat "$MU_OPENLOG"; echo "FAIL dad's run must open his report and his import folder only"; exit 1; }
[ "$(stat -f '%m %i' "$MU_APP/2fa-directory.json")" = "$LIST_STAMP" ] || { echo "FAIL the two-step list was downloaded again within a day"; exit 1; }
pass "two profiles back to back keep separate sign-ins, import folders and reports"

# mom again: her profile is still signed in, so this is an unlock. --logout-after with a bw that cannot
# sign out must end in an error and leave her signed in, not claim she is signed out.
printf 'skip\n' >"$WORK/tty-skip"; printf '\n' >"$WORK/tty-return"
# Before it: ten older reports, a file that is not a report, and a Desktop report left by an earlier version.
for d in 01 02 03 04 05 06 07 08 09 10; do echo old >"$MOM/Reports/Bitwarden Report - mom 2020-01-$d 000000.html"; done
echo keep >"$MOM/Reports/my notes.txt"; echo old >"$MU_HOME/Desktop/Bitwarden Report - mom.html"
DAD_BEFORE="$(snapshot "$DAD")"
CALLS="$(wc -l <"$MU_BWLOG")"
if FAKE_BW_LOGOUT_BUG=fails mu mom@example.com "$WORK/tty-return" --logout-after --user mom >"$WORK/mu3.log" 2>&1; then
  cat "$WORK/mu3.log"; echo "FAIL a run whose sign-out failed ended successfully"; exit 1
fi
expect "$WORK/mu3.log" 'Profile mom is signed in as mom@example.com. Unlock that vault' "a signed-in profile names its account before asking for the password"
bw_calls_since "$CALLS" | grep -qx 'profiles/mom/data unlock --raw' && ! bw_calls_since "$CALLS" | grep -q ' login ' || { echo "FAIL a signed-in profile must unlock, not sign in again"; exit 1; }
expect "$WORK/mu3.log" '^  1  Old Passwords.csv ' "with only an old export left, it is still listed, never taken silently"
expect "$WORK/mu3.log" 'each file that is mom' "the question names the profile"
expect "$WORK/mu3.log" 'Done. The report is open in your browser' "the run itself finished"
expect "$(newest_report "$MOM")" '<strong>0 fixed since [0-9-]+, [0-9]+ left\.</strong>' "a second report compares with the first"
expect "$WORK/mu3.log" "Removed 2 older report\(s\) from $MOM/Reports. The newest 10 are kept" "older reports are removed and counted"
[ "$(ls "$MOM/Reports"/*.html | wc -l | tr -d ' ')" = "10" ] && [ ! -e "$MOM/Reports/Bitwarden Report - mom 2020-01-02 000000.html" ] && [ -e "$MOM/Reports/Bitwarden Report - mom 2020-01-03 000000.html" ] || { ls "$MOM/Reports"; echo "FAIL the newest 10 reports must be kept and the oldest removed"; exit 1; }
[ -f "$MOM/Reports/my notes.txt" ] && [ -f "$MOM/Reports/progress.json" ] && [ "$(snapshot "$DAD")" = "$DAD_BEFORE" ] || { echo "FAIL clearing old reports touched something that is not one of this person's reports"; exit 1; }
expect "$WORK/mu3.log" "An older report, 'Bitwarden Report - mom.html', is still on your Desktop" "a Desktop report from an earlier version is pointed out"
[ -f "$MU_HOME/Desktop/Bitwarden Report - mom.html" ] || { echo "FAIL the old Desktop report was removed without being asked"; exit 1; }
expect "$WORK/mu3.log" 'Profile mom: Bitwarden could NOT be signed out on this Mac' "a failed sign-out after a finished run is an error"
[ -f "$MOM/data/account" ] && [ -f "$MU_DL/Old Passwords.csv" ] || { echo "FAIL test setup: mom should still be signed in and the old export untouched"; exit 1; }
pass "--logout-after reports a sign-out that did not happen"

# A word at the list is refused and asked again; a keyboard that then stops answering is an error.
if mu mom@example.com "$WORK/tty-skip" --user mom exports >"$WORK/mu3b.log" 2>&1; then cat "$WORK/mu3b.log"; echo "FAIL the exports step ended successfully with no usable answer"; exit 1; fi
expect "$WORK/mu3b.log" 'Each answer must be one of the numbers 1 to 1, used once' "a word typed at the list is refused"
expect "$WORK/mu3b.log" 'no answer came from the keyboard' "a keyboard that stops answering is an error, not a silent exit"
[ -f "$MU_DL/Old Passwords.csv" ] || { echo "FAIL an export was moved without being chosen"; exit 1; }

if FAKE_BW_LOGOUT_BUG=silent mu mom@example.com /dev/null --user mom logout >"$WORK/mu4.log" 2>&1; then
  cat "$WORK/mu4.log"; echo "FAIL logout succeeded although bw stayed signed in"; exit 1
fi
expect "$WORK/mu4.log" 'Bitwarden could not be signed out' "logout checks that bw is signed out, not only that bw said so"
mu mom@example.com /dev/null --user mom logout >"$WORK/mu5.log" 2>&1 || { cat "$WORK/mu5.log"; echo "FAIL mom's logout"; exit 1; }
expect "$WORK/mu5.log" 'Profile mom: Bitwarden is signed out on this Mac' "logout signs the profile out"
expect "$WORK/mu5.log" 'still holds files with plain-text passwords: .*/profiles/mom/Bitwarden Import' "logout points at the import files the profile left behind"
[ ! -e "$MOM/data/account" ] && [ -f "$DAD/data/account" ] || { echo "FAIL logout must sign out that profile and no other"; exit 1; }
mu mom@example.com /dev/null logout --user mom >"$WORK/mu6.log" 2>&1 || { cat "$WORK/mu6.log"; echo "FAIL a second logout"; exit 1; }
expect "$WORK/mu6.log" 'Profile mom: Bitwarden was not signed in on this Mac' "a second logout says there was nothing to sign out"
if mu mom@example.com /dev/null --user mmo logout >"$WORK/mu7.log" 2>&1; then cat "$WORK/mu7.log"; echo "FAIL logout of a profile that does not exist succeeded"; exit 1; fi
expect "$WORK/mu7.log" 'no profile named mmo has been used on this Mac. Profiles here: dad mom' "a mistyped profile name is not reported as signed out"
[ ! -e "$MU_APP/profiles/mmo" ] || { echo "FAIL a mistyped logout created a profile"; exit 1; }
pass "logout signs out one profile, checks it, and refuses a name that was never used"

# dad again with --logout-after: unlock, run, lock, then sign out. The remaining old export is skipped.
CALLS="$(wc -l <"$MU_BWLOG")"
mu dad@example.com "$WORK/tty-return" --user dad --logout-after >"$WORK/mu8.log" 2>&1 || { cat "$WORK/mu8.log"; echo "FAIL dad's --logout-after run"; exit 1; }
expect "$WORK/mu8.log" 'Profile dad is signed in as dad@example.com' "the second run of a profile unlocks it"
expect "$WORK/mu8.log" 'No file chosen; skipping the import step. Nothing in Downloads was touched' "Return at the list skips the import step"
[ "$(tail -1 "$WORK/mu8.log")" = "==> Profile dad: Bitwarden is signed out on this Mac." ] || { tail -3 "$WORK/mu8.log"; echo "FAIL --logout-after must end by saying the profile is signed out"; exit 1; }
[ "$(bw_calls_since "$CALLS" | grep -E ' (lock|logout)$' | tr '\n' '|')" = "profiles/dad/data lock|profiles/dad/data logout|" ] || { bw_calls_since "$CALLS"; echo "FAIL the run must lock, then sign out, once each"; exit 1; }
[ ! -e "$DAD/data/account" ] && [ -f "$MU_DL/Old Passwords.csv" ] || { echo "FAIL dad is still signed in, or an export that was not chosen was moved"; exit 1; }
pass "--logout-after locks and signs the profile out when the run ends"

# The dedupe step for a profile, with --user after the step words: the plan lands in that profile's folder.
rm "$MU_DL/Old Passwords.csv"
mu kelly@example.com /dev/null dedupe exact --user kelly >"$WORK/mu9.log" 2>&1 || { cat "$WORK/mu9.log"; echo "FAIL a profile's dedupe preview"; exit 1; }
expect "$WORK/mu9.log" 'Plan: .*/profiles/kelly/Dedupe Plan/plan-exact.md' "a profile's dedupe plan is written to its own folder"
[ -f "$MU_APP/profiles/kelly/Dedupe Plan/plan-exact.md" ] && [ ! -e "$MU_APP/Dedupe Plan" ] && [ ! -e "$MOM/Dedupe Plan" ] || { echo "FAIL the dedupe plan landed outside the profile's folder"; exit 1; }
mu kelly@example.com "$WORK/tty-skip" --user kelly exports >"$WORK/mu9b.log" 2>&1 || { cat "$WORK/mu9b.log"; echo "FAIL a profile's exports step"; exit 1; }
expect "$WORK/mu9b.log" "To import kelly's old passwords, put their export in the Downloads folder of this Mac" "with no export, a profile is told to bring that person's own export"
expect "$WORK/mu9b.log" "not kelly's" "the prompt warns that this Mac's Passwords app is not that person's"
pass "dedupe and exports follow the profile"

# No --user: the shared sign-in and folders, and the silent export pick-up, as before profiles.
MOM_BEFORE="$(snapshot "$MOM")"; DAD_BEFORE="$(snapshot "$DAD")"
cp "$FX/chrome.csv" "$MU_DL/Google Passwords.csv"
CALLS="$(wc -l <"$MU_BWLOG")"
mu owner@example.com /dev/null >"$WORK/mu10.log" 2>&1 || { cat "$WORK/mu10.log"; echo "FAIL a run without --user"; exit 1; }
! grep -q 'Profile\|Type the number' "$WORK/mu10.log" || { cat "$WORK/mu10.log"; echo "FAIL a run without --user mentioned a profile or asked which export to take"; exit 1; }
expect "$WORK/mu10.log" '^==> Sign in to Bitwarden. Type your email, then your master password \(nothing shows while typing\), then the two-step code if asked\.$' "without --user the sign-in wording is unchanged"
expect "$WORK/mu10.log" "Moved Google Passwords.csv to Bitwarden Import/chrome-passwords-$TODAY.csv" "without --user a fresh export is still picked up without asking"
! bw_calls_since "$CALLS" | grep -qv '^data ' || { bw_calls_since "$CALLS"; echo "FAIL a run without --user must use the shared data folder only"; exit 1; }
[ -f "$MU_APP/data/account" ] && [ -f "$MU_APP/Bitwarden Import/new-for-bitwarden.csv" ] || { echo "FAIL a run without --user must use the shared sign-in and import folder"; exit 1; }
expect "$(newest_report "$MU_APP")" '<td>Logins with a password</td><td>5</td>' "without --user the report goes to the shared Reports folder"
[ "$(ls "$MU_APP/Reports" | tr '\n' '|' | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{6}/STAMP/')" = "Bitwarden Report STAMP.html|progress.json|" ] || { ls "$MU_APP/Reports"; echo "FAIL the shared Reports folder must hold one dated report and the progress file"; exit 1; }
[ "$(tail -1 "$WORK/mu10.log")" = "==> Done. The report is open in your browser. It is kept in $MU_APP/Reports, not on the Desktop. Your vault is locked again." ] || { tail -2 "$WORK/mu10.log"; echo "FAIL without --user the closing line must name the shared Reports folder"; exit 1; }
[ "$(ls -A "$MU_HOME/Desktop")" = "Bitwarden Report - mom.html" ] && ! grep -q 'older report' "$WORK/mu10.log" || { echo "FAIL a run without --user wrote to the Desktop, or pointed at another person's old report"; exit 1; }
[ "$(bw_calls_since "$CALLS" | tail -1)" = "data lock" ] || { echo "FAIL without --logout-after the run must end by locking, not signing out"; exit 1; }
[ "$(snapshot "$MOM")" = "$MOM_BEFORE" ] && [ "$(snapshot "$DAD")" = "$DAD_BEFORE" ] || { echo "FAIL a run without --user changed a profile's folder"; exit 1; }
mu owner@example.com /dev/null logout >"$WORK/mu11.log" 2>&1 || { cat "$WORK/mu11.log"; echo "FAIL logout without --user"; exit 1; }
expect "$WORK/mu11.log" '^==> Bitwarden is signed out on this Mac\.$' "logout without --user signs out the shared sign-in"
[ ! -e "$MU_APP/data/account" ] || { echo "FAIL the shared sign-in is still signed in"; exit 1; }
pass "without --user everything is where it was; logout works there too"

# No person is named in the tool, its messages, its tests or its docs: whoever shares the paste line is
# "the person who sent you this line". Cannot catch a name other than the one it looks for.
! git grep -nw -e 'R[o]b' -- . ':!tests/fixture' || { echo "FAIL a personal name is hard-coded in the tool, its tests or its docs"; exit 1; }
expect bw-health.sh 'Send a screenshot of this window to the person who sent you this line' "the generic failure message names no one"
expect bw_dedupe.py 'tell the person who sent you this line what this window printed' "the read-back stop message names no one"
pass "no personal name is hard-coded; messages say 'the person who sent you this line'"

# The README names every fetched file and test file, and its paste lines use the tag of the script's version.
# Cannot catch a wrong description, only a missing or renamed file.
for f in bw-health.sh $FILES tests/run.sh; do
  grep -qF "\`$f\`" README.md || { echo "FAIL README does not mention $f"; exit 1; }
done
BASE="https://raw.githubusercontent.com/nellirob92/bw-health/v$VERSION"
grep -qxF 'RELEASE_URL="https://raw.githubusercontent.com/nellirob92/bw-health/v$VERSION"' bw-health.sh || { echo "FAIL bw-health.sh must fetch from the tag of its own VERSION"; exit 1; }
[ "$(grep -c 'curl -fsSL' README.md)" -gt 0 ] && [ "$(grep -c 'curl -fsSL' README.md)" = "$(grep -cF "curl -fsSL $BASE/bw-health.sh" README.md)" ] || { echo "FAIL every README paste line must use the tag of the script's VERSION ($BASE)"; exit 1; }
pass "the README names every fetched file and its paste lines are pinned to the script's version tag"

echo; echo "ALL TESTS PASSED"
