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
uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --out "$WORK/report.md"
expect "$WORK/report.md" '^\| Logins with a password \| 5 \|' "report counts live logins"
expect "$WORK/report.md" '^\| In trash \(ignored, empty it\) \| 1 \|' "report excludes trash"
expect "$WORK/report.md" '^\| Reused \(accounts sharing a password\) \| 3 \|' "report counts reused logins"
expect "$WORK/report.md" 'Password group 1: used 3 times' "report shows reuse count"
expect "$WORK/report.md" '^\| Weak \| 4 \|' "report counts weak"
expect "$WORK/report.md" '^\| Duplicate entries \(same site \+ username\) \| 2 \|' "report counts duplicates"
expect "$WORK/report.md" '^\| 1 - email / Apple / Google \| Gmail' "report ranks email first"
expect "$WORK/report.md" '^\| 4 - everything else \| Netflix' "report does not match x.com inside netflix.com"
expect "$WORK/report.md" 'not checked \(--no-hibp\)' "report marks breach check skipped"
! grep -q 'password123' "$WORK/report.md" || { echo "FAIL a password leaked into the report"; exit 1; }
pass "report never prints a password"

# --- report: breach check against Have I Been Pwned ---------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --out "$WORK/report-hibp.md"
expect "$WORK/report-hibp.md" '^\| Exposed in a breach \| 4 \|' "breach check flags the known-breached passwords"
expect "$WORK/report-hibp.md" '^\| Gmail \(mom@gmail.com\) - accounts.google.com \| [0-9,]+ \|' "breach table has a count"

# --- report: html -------------------------------------------------------------------------
uv run --quiet bw_report.py --input "$FX/items.json" --no-hibp --html --out "$WORK/report.html"
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
  1:status:) echo '{"status":"unlocked"}' ;;
  1:sync:) echo 'Syncing complete.' ;;
  2:list:items) cat "$FX/items.json" ;;
  *) echo "Invalid command: \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$WORK/fakebin/bw"
PATH="$WORK/fakebin:$PATH" BW_SESSION=fake uv run --quiet bw_report.py --no-hibp --out "$WORK/report-live.md"
expect "$WORK/report-live.md" '^\| Logins with a password \| 5 \|' "live path reads the vault through bw list items"

# --- report: password shapes a real vault has and the fixture lacks -----------------------
# A 200-character password (zxcvbn refuses anything over 72) and a non-ASCII one. Pins that the
# report completes and counts them; it cannot catch a shape neither of these is.
LONG_PW="$(printf 'Qx7!mZ2@%.0s' $(seq 1 25))"
/usr/bin/jq --arg long "$LONG_PW" '. + [
  {"id":"90","type":1,"name":"Long","deletedDate":null,"login":{"username":"a@b.com","password":$long,"uris":[{"uri":"https://long.example.com"}]}},
  {"id":"91","type":1,"name":"Unicode","deletedDate":null,"login":{"username":"c@d.com","password":"pässwörd-日本語-🔑","uris":[{"uri":"https://uni.example.com"}]}}
]' "$FX/items.json" >"$WORK/items-shapes.json"
uv run --quiet bw_report.py --input "$WORK/items-shapes.json" --no-hibp --out "$WORK/report-shapes.md"
expect "$WORK/report-shapes.md" '^\| Logins with a password \| 7 \|' "a 200-character and a non-ASCII password are scored, not fatal"

# --- report: a copy of the same account is not reuse --------------------------------------
# Copies of Gmail (inside a reuse group) and Chase (unique password): same site, username and
# password. Pins that copies add nothing to the reuse counts or the fix list; it cannot catch a
# copy whose site or username is spelled differently, which is a different account here.
/usr/bin/jq '. + [
  {"id":"92","type":1,"name":"Gmail copy","deletedDate":null,"login":{"username":"mom@gmail.com","password":"password123","uris":[{"uri":"https://accounts.google.com"}]}},
  {"id":"93","type":1,"name":"Chase copy","deletedDate":null,"login":{"username":"mom","password":"Xk9#mPq2$vL7nR4wZ!t8","uris":[{"uri":"https://chase.com"}]}}
]' "$FX/items.json" >"$WORK/items-copies.json"
uv run --quiet bw_report.py --input "$WORK/items-copies.json" --no-hibp --out "$WORK/report-copies.md"
expect "$WORK/report-copies.md" '^\| Reused \(accounts sharing a password\) \| 3 \|' "copies of one account do not count as reuse"
expect "$WORK/report-copies.md" '^\| \*\*Logins that need a new password\*\* \| \*\*3\*\* \|' "the fix list counts accounts (Gmail, Roblox, Netflix), not copies"

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
uv run --quiet bw_report.py --input "$WORK/items-badurl.json" --no-hibp --out "$WORK/report-badurl.md"
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
[ -f "$FAKE_HOME/Library/Application Support/bw-health/bw_report.py" ] || { echo "FAIL scripts not fetched"; exit 1; }
pass "installer put bw and the scripts in the app folder"
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
expect "$WORK/dd1.log" '^2 group\(s\) to change, 9 left alone, 8 for the other stage' "exact stage counts its groups, the blocked ones and the merge ones"
expect "$WORK/dd2.log" '^8 group\(s\) to change, 9 left alone, 2 for the other stage' "merge stage counts its groups"
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
expect "$WORK/dd8.log" '^0 group\(s\) to change, 9 left alone, 0 for the other stage' "a second merge run finds nothing left to do"
expect "$WORK/dd9.log" '^0 group\(s\) to change, 9 left alone, 0 for the other stage' "a second exact run finds nothing left to do"
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
# k1: the passkey copy holds the older password. s1: skipped with Enter. x1 also has two seeds, b4
# differs only by seeds: both stay left alone. Zoom (m2) is for the merge stage. Cannot catch the real
# bw reporting passwordRevisionDate differently from this model.
expect "$WORK/dd2.log" 'different passwords: dedupe pick' "exact and merge point to the pick stage for different-password groups"
/usr/bin/jq '[.[] | select(.id | test("^(b1|b4|m2)"))] | map(if .id == "b1a" then .login.passwordRevisionDate = "2026-03-05T12:00:00Z" else . end) + [
  {"id":"k1a","type":1,"organizationId":null,"name":"Kay","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2025-01-01T00:00:00Z","revisionDate":"2025-06-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"k@x.com","password":"PW-secret-k1-old","passwordRevisionDate":null,"totp":null,"fido2Credentials":[{"credentialId":"cred-k1","keyValue":"KEYDATA-k1","rpId":"k1.example.com"}],"uris":[{"match":null,"uri":"https://k1.example.com"}]}},
  {"id":"k1b","type":1,"organizationId":null,"name":"Kay","notes":null,"folderId":null,"favorite":false,"reprompt":0,"creationDate":"2025-02-01T00:00:00Z","revisionDate":"2026-04-02T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"k@x.com","password":"PW-secret-k1-new","passwordRevisionDate":"2026-04-01T09:30:00Z","totp":null,"uris":[{"match":null,"uri":"https://k1.example.com"}]}},
  {"id":"s1a","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":"fA","favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"s@x.com","password":"PW-secret-s1-a","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"s1b","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"s@x.com","password":"PW-secret-s1-b","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"s1c","type":1,"organizationId":null,"name":"Odd folder","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2025-12-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"s@x.com","password":"","totp":null,"uris":[{"match":null,"uri":"https://s1.example.com"}]}},
  {"id":"x1a","type":1,"organizationId":null,"name":"Both","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-01-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"x@x.com","password":"PW-secret-x1-a","totp":"otpauth://totp/x?secret=AAAA","uris":[{"match":null,"uri":"https://x1.example.com"}]}},
  {"id":"x1b","type":1,"organizationId":null,"name":"Both","notes":null,"folderId":null,"favorite":false,"reprompt":0,"revisionDate":"2026-02-01T00:00:00Z","deletedDate":null,"fields":[],"login":{"username":"x@x.com","password":"PW-secret-x1-b","totp":"otpauth://totp/x?secret=BBBB","uris":[{"match":null,"uri":"https://x1.example.com"}]}}]' "$FX/dupes.json" >"$WORK/state-pick.json"
cp "$WORK/state-pick.json" "$WORK/state-pick-before.json"
pick() { # pick <tty file> <log> <args...>
  local tty="$1" log="$2"; shift 2
  ( STATE="$WORK/state-pick.json"; BWLOG="$WORK/bw-pick.log"; export TZ=UTC; dedupe "$tty" pick "$@" >"$log" 2>&1 )
}
: >"$WORK/bw-pick.log"
pick "$WORK/tty-no" "$WORK/pk1.log" || { cat "$WORK/pk1.log"; echo "FAIL pick dry run"; exit 1; }
expect "$WORK/pk1.log" '^3 group\(s\) to change, 2 left alone, 1 for the other stage' "pick counts only groups whose sole conflict is the password"
expect "$WORK/pk1.log" 'Left alone: 2 different one-time-code seeds' "a group with different passwords and another conflict stays left alone, with that reason"
expect "$WORK/pk1.log" '^ +1 +"Bank one" +folder: no folder +password changed 2026-03-05 12:00, edited 2026-01-01 00:00$' "the newest password is listed first, with its dates in local time"
expect "$WORK/pk1.log" '^ +2 +"Bank one" +folder: no folder +edited 2026-02-01 00:00 +\(kept entry\)$' "a copy edited later but with an older password ranks second"
expect "$WORK/pk1.log" '^ +1 +"Kay" .*password changed 2026-04-01 09:30, edited 2026-04-02 00:00, created 2025-02-01 00:00$' "every date bw reports is shown"
expect "$WORK/pk1.log" '^ +2 +"Kay" .*\(kept entry, holds a passkey\)$' "the passkey copy is the kept entry even with the older password"
expect "$WORK/pk1.log" 'Nothing was changed' "a pick dry run changes nothing"
cmp -s "$WORK/state-pick.json" "$WORK/state-pick-before.json" && ! grep -qE '^(edit|delete) ' "$WORK/bw-pick.log" || { echo "FAIL a pick dry run changed the vault"; exit 1; }

printf '9\n\n3\n' >"$WORK/tty-skip"
pick "$WORK/tty-skip" "$WORK/pk2.log" --apply || { cat "$WORK/pk2.log"; echo "FAIL skipping every group must end cleanly"; exit 1; }
expect "$WORK/pk2.log" 'not one of the numbers shown, so this group is skipped' "an answer that is not a listed number skips the group"
expect "$WORK/pk2.log" 'That copy has no password, so this group is skipped' "choosing a copy with no password skips the group instead of blanking the password"
expect "$WORK/pk2.log" 'No group was chosen. Nothing was changed.' "skipping every group changes nothing"
! grep -q 'Type DEDUPE' "$WORK/pk2.log" || { echo "FAIL the confirmation was asked with nothing chosen"; exit 1; }
printf '1\n1\n\nno\n' >"$WORK/tty-pick-no"
if pick "$WORK/tty-pick-no" "$WORK/pk3.log" --apply; then echo "FAIL pick went ahead without the confirmation word"; exit 1; fi
expect "$WORK/pk3.log" 'This will edit 2 kept copies and move 2 copies to the Bitwarden trash' "pick states the edits and the trashing before the confirmation"
cmp -s "$WORK/state-pick.json" "$WORK/state-pick-before.json" && ! grep -qE '^(edit|delete) ' "$WORK/bw-pick.log" || { echo "FAIL an unconfirmed pick changed the vault"; exit 1; }
pass "pick ranks by password date, previews, and changes nothing until a group is chosen and DEDUPE typed"

printf '1\n1\n\nDEDUPE\n' >"$WORK/tty-pick"
pick "$WORK/tty-pick" "$WORK/pk4.log" --apply || { cat "$WORK/pk4.log"; echo "FAIL pick apply"; exit 1; }
pv() { /usr/bin/jq -r --arg id "$1" ".[] | select(.id == \$id) | $2" "$WORK/state-pick.json"; }
[ "$(pv b1b .login.password)" = "PW-secret-b1-old" ] && [ "$(pv b1a .deletedDate)" != "null" ] && [ "$(pv b1b .deletedDate)" = "null" ] || { echo "FAIL the chosen password was not saved on the kept copy, or the other copy not trashed"; exit 1; }
[ "$(pv k1a .login.password)" = "PW-secret-k1-new" ] && [ "$(pv k1a '.login.fido2Credentials[0].keyValue')" = "KEYDATA-k1" ] && [ "$(pv k1b .deletedDate)" != "null" ] || { echo "FAIL the passkey copy must keep its passkey and take the chosen password"; exit 1; }
[ "$(pv s1a .deletedDate)" = "null" ] && [ "$(pv s1b .deletedDate)" = "null" ] && [ "$(pv s1a .login.password)" = "PW-secret-s1-a" ] || { echo "FAIL a skipped group was changed"; exit 1; }
[ "$(/usr/bin/jq '[.[] | select(.id | test("^(x1|b4|m2)")) | select(.deletedDate == null)] | length' "$WORK/state-pick.json")" = "6" ] && ! grep -qE '^(edit|delete) item (x1|b4|m2|s1)' "$WORK/bw-pick.log" || { echo "FAIL pick touched a group it does not act on"; exit 1; }
[ "$(grep -c '^get item' "$WORK/bw-pick.log")" = "2" ] || { echo "FAIL every pick edit must be read back"; exit 1; }
! grep -q 'PW-secret\|KEYDATA' "$WORK/pk1.log" "$WORK/pk2.log" "$WORK/pk3.log" "$WORK/pk4.log" "$PLANS/plan-pick.md" || { echo "FAIL a password or passkey key reached the terminal or the plan"; exit 1; }
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

# No person is named in the tool, its messages, its tests or its docs: whoever shares the paste line is
# "the person who sent you this line". Cannot catch a name other than the one it looks for.
! git grep -nw -e 'R[o]b' -- . ':!tests/fixture' || { echo "FAIL a personal name is hard-coded in the tool, its tests or its docs"; exit 1; }
expect bw-health.sh 'Send a screenshot of this window to the person who sent you this line' "the generic failure message names no one"
expect bw_dedupe.py 'tell the person who sent you this line what this window printed' "the read-back stop message names no one"
pass "no personal name is hard-coded; messages say 'the person who sent you this line'"

# The README names every script and test file, and its paste line uses the script's own base URL.
# Cannot catch a wrong description, only a missing or renamed file.
for f in bw-health.sh bw_*.py tests/run.sh; do
  grep -qF "\`$f\`" README.md || { echo "FAIL README does not mention $f"; exit 1; }
done
BASE="$(sed -n 's/^BASE_URL=.*:-\(.*\)}"$/\1/p' bw-health.sh)"
[ -n "$BASE" ] && [ "$(grep -c 'curl -fsSL' README.md)" = "$(grep -cF "curl -fsSL $BASE/bw-health.sh" README.md)" ] || { echo "FAIL every README paste line must use the script's BASE_URL ($BASE)"; exit 1; }
pass "the README names every script and uses the script's own URL"

echo; echo "ALL TESTS PASSED"
