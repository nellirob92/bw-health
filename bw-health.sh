#!/bin/bash
# One-line Bitwarden password check-up for a Mac. Read-only on the vault.
#   curl -fsSL <BASE_URL>/bw-health.sh | bash                          # full run: report, then export staging
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- check              # install only
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- dedupe exact|merge|pick # duplicate cleanup preview (read-only)
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- dedupe merge apply [N]   # act on it, after a typed confirmation
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- logout             # sign out of Bitwarden on this Mac
#   bash bw-health.sh exports                                          # stage Downloads exports only
# Several people on one Mac account: add --user NAME to any line (own sign-in, folders and reports),
# and --logout-after to sign that person out when the run ends.
# <BASE_URL> is a release tag (see VERSION below), never main.
# Only the dedupe step ever changes the vault; see README.md.

set -euo pipefail

say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\nSomething went wrong: %s\nSend a screenshot of this window to the person who sent you this line.\n' "$*" >&2; exit 1; }

# --- what to run, and for whom: checked before anything is installed or asked ------------------
# --user NAME and --logout-after may sit anywhere on the line; the words left over are the step.
PROFILE=""; PROFILE_GIVEN=0; LOGOUT_AFTER=0; words=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --user)
      [ "$PROFILE_GIVEN" = 0 ] || fail "--user was given twice"
      [ "$#" -ge 2 ] || fail "--user needs a name after it, for example: --user mom"
      PROFILE="$2"; PROFILE_GIVEN=1; shift 2 ;;
    --logout-after) LOGOUT_AFTER=1; shift ;;
    --*) fail "unknown option: $1" ;;
    *) words+=("$1"); shift ;;
  esac
done
set -- ${words[@]+"${words[@]}"}
if [ "$PROFILE_GIVEN" = 1 ]; then
  [[ "$PROFILE" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || fail "a --user name is 1 to 32 lowercase letters, digits or hyphens, and starts with a letter or digit (for example: mom)"
fi
case "${1:-}" in
  "") ;;
  check|exports|logout)
    [ -z "${2:-}" ] || fail "nothing is allowed after $1"
    [ "$LOGOUT_AFTER" = 0 ] || fail "--logout-after goes with a run that signs in, not with $1" ;;
  dedupe)
    case "${2:-}" in exact|merge|pick) ;; *) fail "use: dedupe exact, dedupe merge or dedupe pick. Add apply to act, then a number to limit how many groups." ;; esac
    case "${3:-}" in ""|apply) ;; *) fail "after the stage, the only word allowed is apply" ;; esac
    [ -z "${4:-}" ] || { [ "${3:-}" = apply ] && [[ "$4" =~ ^[1-9][0-9]*$ ]]; } || fail "a limit goes after apply and is a whole number, 1 or more"
    [ -z "${5:-}" ] || fail "nothing is allowed after the limit" ;;
  *) fail "unknown step: $1. Leave it out for the check-up, or use check, exports, dedupe or logout." ;;
esac

# A release is a tag. This script fetches its files from the tag of its own version and uses each
# one only if it matches the checksum below, so no run depends on whatever is on main.
VERSION="1.0.0"
RELEASE_URL="https://raw.githubusercontent.com/nellirob92/bw-health/v$VERSION"
BASE_URL="${BW_HEALTH_BASE_URL:-$RELEASE_URL}"
FILES="bw_report.py bw_import_diff.py bw_dedupe.py fix_order.txt"
# SHA-256 of each fetched file. `bash tests/run.sh` fails, and prints the right value, when one is stale.
pinned_sha256() { # <file name>
  case "$1" in
    bw_report.py)      echo "838995eee820adf6284e142b47fafde28107b6b6c651aea9a67bd8384e2ca7fe" ;;
    bw_import_diff.py) echo "5c01fa14640d0de6e844cde52944cbef8d116ed91fb2ce3f064430ff17bdf37c" ;;
    bw_dedupe.py)      echo "8d55188435ddfd668a63059c365b33a8bca5842343c886713c6f88cc09623eea" ;;
    fix_order.txt)     echo "2b5f17f989ff070ada47bcf0b1ccb71e888b94143ae2cdd1a7b68d8d821525a5" ;;
    *) fail "no checksum is written in bw-health.sh for $1" ;;
  esac
}
APP_DIR="$HOME/Library/Application Support/bw-health"
BIN_DIR="$APP_DIR/bin"
# A profile (--user NAME) has its own sign-in, import folder, dedupe plan and reports, so several
# people can take turns on one Mac account. Without one, the shared folder is used.
if [ -n "$PROFILE" ]; then
  PROFILE_DIR="$APP_DIR/profiles/$PROFILE"; REPORT_NAME="Bitwarden Report - $PROFILE"; TAG="Profile $PROFILE: "
else
  PROFILE_DIR="$APP_DIR"; REPORT_NAME="Bitwarden Report"; TAG=""
fi
# Under Library, never Desktop or Documents: iCloud would upload the plain-text exports, and the
# reports list every site and username.
IMPORT_DIR="$PROFILE_DIR/Bitwarden Import"
DEDUPE_DIR="$PROFILE_DIR/Dedupe Plan"
REPORTS_DIR="$PROFILE_DIR/Reports"
KEEP_REPORTS=10
UV="$HOME/.local/bin/uv"
BW="$BIN_DIR/bw"
# Pinned: the download is a release file, not a GitHub API lookup (the API rate-limits shared IPs).
# To bump, take both hashes from the cli-v<version> release assets' sha256 digests.
BW_CLI_VERSION="2026.10.0"
BW_CLI_SHA256_ARM64="062c880508678b8d936ab2522a3a1e92d60f52b5c534e71406e9b47329e95207"
BW_CLI_SHA256_X64="39602a597ca63127c22ee3844546f3fe06079e4f67be7b9a7ea4e30ede8721d0"

# Run as a file with its files beside it (a clone), this uses those, so a branch can be tried
# before it is released. Piped from curl there is no file, and BW_HEALTH_BASE_URL still wins.
# Wherever a file comes from, it is used only if it matches its checksum above.
LOCAL_SRC=""
if [ -z "${BW_HEALTH_BASE_URL:-}" ] && [ -n "${BASH_SOURCE[0]:-}" ]; then
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  beside=0
  for f in $FILES; do [ ! -f "$self_dir/$f" ] || beside=$((beside + 1)); done
  case "$beside" in
    0) ;;
    4) LOCAL_SRC="$self_dir" ;;
    *) fail "only some of this tool's files are beside bw-health.sh in $self_dir. Expected all four ($FILES), or none." ;;
  esac
fi
fetch_file() { # <file name>: into APP_DIR, and only if it matches its pinned checksum
  local f="$1" new="$APP_DIR/$1.new" want got
  want="$(pinned_sha256 "$f")" || exit 1
  if [ -n "$LOCAL_SRC" ]; then
    cp "$LOCAL_SRC/$f" "$new" || fail "could not copy $f"
  else
    curl -fsSL "$BASE_URL/$f" -o "$new" || fail "could not download $f"
  fi
  got="$(shasum -a 256 "$new" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    rm -f "$new"
    fail "$f did not match the checksum written in bw-health.sh, so it was not used${LOCAL_SRC:+. If you changed it, update its checksum (see README, For maintainers)}"
  fi
  mv "$new" "$APP_DIR/$f"
}
# Only the newest KEEP_REPORTS reports are kept, and only this person's Reports folder is touched.
# The names carry the time, so the sorted list is oldest first.
prune_reports() {
  local all=() extra i
  shopt -s nullglob
  all=("$REPORTS_DIR/$REPORT_NAME "*.html)
  shopt -u nullglob
  extra=$(( ${#all[@]} - KEEP_REPORTS ))
  [ "$extra" -gt 0 ] || return 0
  for ((i = 0; i < extra; i++)); do
    rm "${all[$i]}" || fail "could not remove an old report: ${all[$i]}"
  done
  say "Removed $extra older report(s) from $REPORTS_DIR. The newest $KEEP_REPORTS are kept."
}

# A failed unlock is almost always a mistyped master password; say so in plain words (bw's own lines stay above it).
fail_unlock() {
  cat >&2 <<'EOT'

That did not unlock your Bitwarden vault. Nothing in your vault was changed.

This almost always means the master password was typed wrong. Nothing shows on the screen while
you type, so it is easy to slip. Check that Caps Lock is off, then run the same line again.

The lines above that say "decryption operation failed" are Bitwarden saying the same thing:
the password did not match.

Still failing? Please stop after two tries and check the password by signing in at
vault.bitwarden.com. If that fails too, the password is the problem, not this tool.
EOT
  exit 1
}

fail_login() {
  cat >&2 <<'EOT'

Sign-in did not complete. Nothing in your vault was changed.

Check the email address and the master password. Nothing shows on the screen while you type, so
check that Caps Lock is off. If Bitwarden asked for a code, use the newest one, because codes
expire after a few minutes. Then run the same line again.

Still failing? Please stop after two tries and check your email and password by signing in at
vault.bitwarden.com.
EOT
  exit 1
}

# chrome | apple | other | "" (not a password export), from the csv header
export_kind() {
  local header; header="$(head -1 "$1" | tr -d '\r')"
  grep -qiE '(^|,)"?(password|login_password)"?(,|$)' <<<"$header" || return 0
  if grep -qiE '^"?title"?,"?url"?,' <<<"$header"; then echo apple
  elif grep -qiE '^"?name"?,"?url"?,' <<<"$header"; then echo chrome
  elif grep -qiE '(^|,)"?(url|login_uri)"?(,|$)' <<<"$header"; then echo other
  fi
}

# Move EVERY password export in Downloads into IMPORT_DIR, renamed by kind and date, so one
# trash step covers them all. Every export from the last 7 days feeds the diff, newest first
# (two Google accounts give two files); none fresh triggers a re-export prompt.
STAGED=()
MOVED=0
TTY="${BW_HEALTH_TTY:-/dev/tty}"
# The keyboard is opened once, so successive answers are successive lines (under curl | bash,
# stdin is the script itself).
KEYBOARD_OPEN=0
ask() { # <prompt>; sets ANSWER
  if [ "$KEYBOARD_OPEN" = 0 ]; then
    exec 3<"$TTY" || fail "could not read from the keyboard"
    KEYBOARD_OPEN=1
  fi
  printf '%s' "$1"
  read -r ANSWER <&3 || fail "no answer came from the keyboard"
}
move_export() { # <file> <kind> <mtime>; sets LAST_DEST
  local base n=2
  base="$IMPORT_DIR/$2-passwords-$(date -r "$3" +%Y-%m-%d)"
  LAST_DEST="$base.csv"
  while [ -e "$LAST_DEST" ]; do LAST_DEST="$base-$n.csv"; n=$((n + 1)); done
  mv "$1" "$LAST_DEST" || fail "could not move $(basename "$1")"
  chmod 600 "$LAST_DEST"
  MOVED=$((MOVED + 1))
  say "Moved $(basename "$1") to Bitwarden Import/$(basename "$LAST_DEST")"
}
stage_exports() {
  local attempt f kind mtime cutoff stale_note fresh
  if [ -n "$PROFILE" ]; then pick_exports; return 0; fi
  mkdir -p "$IMPORT_DIR"
  for attempt in 1 2; do
    stale_note=""; fresh=""
    cutoff=$(( $(date +%s) - 7*24*3600 ))
    shopt -s nullglob
    for f in "$HOME/Downloads"/*.csv "$HOME/Downloads"/*.CSV; do
      kind="$(export_kind "$f")"; [ -n "$kind" ] || continue
      mtime="$(stat -f %m "$f")"
      if [ "$mtime" -lt "$cutoff" ]; then
        stale_note="$stale_note
  - $(basename "$f") ($kind, from $(date -r "$mtime" +%Y-%m-%d)) is older than 7 days"
        move_export "$f" "$kind" "$mtime"
      else
        fresh="$fresh$mtime	$kind	$f
"
      fi
    done
    shopt -u nullglob
    [ -z "$fresh" ] || break
    [ "$attempt" = 1 ] || { say "Still no fresh export; skipping the import step"; return 0; }
    say "No password export from the last 7 days in Downloads.${stale_note}"
    cat <<'EOT'
To import old passwords, export them now (the file lands in Downloads):
  Chrome: go to passwords.google.com, click the gear, then Export passwords.
  Apple:  open the Passwords app on this Mac, File menu, Export All Passwords.
EOT
    ask 'Press Return when the export is done, or type skip and Return: '
    [ "$ANSWER" != "skip" ] || { say "Skipping the import step"; return 0; }
  done
  while IFS="$(printf '\t')" read -r mtime kind f; do
    move_export "$f" "$kind" "$mtime"
    STAGED+=("$LAST_DEST")
  done <<<"$(printf '%s' "$fresh" | sort -rn)"
}

# A profile run never takes a file on its own: Downloads can hold several people's exports at
# once. Every password export is listed, and only the ones typed for this person are moved and
# compared. The rest stay in Downloads, untouched.
pick_exports() {
  local attempt f kind mtime found i n tok ok chosen old cutoff left tab
  local files=() kinds=() mtimes=() picks=()
  tab="$(printf '\t')"
  mkdir -p "$IMPORT_DIR"
  for attempt in 1 2; do
    found=""
    shopt -s nullglob
    for f in "$HOME/Downloads"/*.csv "$HOME/Downloads"/*.CSV; do
      kind="$(export_kind "$f")"; [ -n "$kind" ] || continue
      found="$found$(stat -f %m "$f")$tab$kind$tab$f
"
    done
    shopt -u nullglob
    [ -z "$found" ] || break
    [ "$attempt" = 1 ] || { say "Still no password export in Downloads; skipping the import step"; return 0; }
    say "No password export in Downloads."
    cat <<EOT
To import $PROFILE's old passwords, put their export in the Downloads folder of this Mac now:
  Chrome: sign in at passwords.google.com as $PROFILE, click the gear, then Export passwords.
  Apple:  on $PROFILE's own Mac, open the Passwords app, File menu, Export All Passwords,
          then AirDrop the file to this Mac. The Passwords app on this Mac holds the passwords
          of this Mac's own Apple Account, not $PROFILE's.
EOT
    ask 'Press Return when the export is in Downloads, or type skip and Return: '
    [ "$ANSWER" != "skip" ] || { say "Skipping the import step"; return 0; }
  done
  while IFS="$tab" read -r mtime kind f; do
    files+=("$f"); kinds+=("$kind"); mtimes+=("$mtime")
  done <<<"$(printf '%s' "$found" | sort -rn)"
  n="${#files[@]}"
  cutoff=$(( $(date +%s) - 7*24*3600 ))
  say "Password exports in Downloads, newest first:"
  for ((i = 0; i < n; i++)); do
    old=""; [ "${mtimes[$i]}" -ge "$cutoff" ] || old=", older than 7 days"
    printf '  %d  %s  (%s, saved %s%s)\n' "$((i + 1))" "$(basename "${files[$i]}" | tr -d '[:cntrl:]')" \
      "${kinds[$i]}" "$(date -r "${mtimes[$i]}" '+%Y-%m-%d %H:%M')" "$old"
  done
  while :; do
    ask "Type the number of each file that is $PROFILE's, with spaces between (for example: 1 2), or press Return to skip: "
    [ -n "$ANSWER" ] || { say "No file chosen; skipping the import step. Nothing in Downloads was touched."; return 0; }
    read -r -a picks <<<"$ANSWER"
    chosen=" "; ok=1
    for tok in "${picks[@]}"; do
      if [[ "$tok" =~ ^[1-9][0-9]{0,2}$ ]] && [ "$tok" -le "$n" ] && [[ "$chosen" != *" $tok "* ]]; then
        chosen="$chosen$tok "
      else
        ok=0
      fi
    done
    [ "$ok" = 0 ] || break
    # The answer is never echoed: it could be a password typed by mistake.
    echo "Each answer must be one of the numbers 1 to $n, used once. Nothing was moved."
  done
  for ((i = 0; i < n; i++)); do
    [[ "$chosen" == *" $((i + 1)) "* ]] || continue
    move_export "${files[$i]}" "${kinds[$i]}" "${mtimes[$i]}"
    STAGED+=("$LAST_DEST")
  done
  left=$((n - ${#STAGED[@]}))
  [ "$left" = 0 ] || say "$left other password export file(s) are still in Downloads, untouched. They hold plain-text passwords: trash them once their owner's run is done."
}

bw_status() { "$BW" status | /usr/bin/jq -r "$1"; } # <jq filter>
sign_out() { "$BW" logout </dev/null >/dev/null && [ "$(bw_status .status)" = "unauthenticated" ]; }
account_email() {
  local email
  email="$(bw_status '.userEmail // empty')" || fail "could not read Bitwarden's sign-in status"
  [ -n "$email" ] || fail "Bitwarden did not say which account profile $PROFILE is signed in as"
  printf '%s' "$email"
}
# Runs however the run ends once sign-in has succeeded: the vault is always locked, and the
# account is signed out when --logout-after asked for it.
finish() {
  local code=$?
  "$BW" lock >/dev/null 2>&1 || true
  if [ "$LOGOUT_AFTER" = 1 ]; then
    if sign_out; then
      say "${TAG}Bitwarden is signed out on this Mac."
    else
      printf '\n%sBitwarden could NOT be signed out on this Mac. Run the line again with logout in place of --logout-after.\n' "$TAG" >&2
      code=1
    fi
  fi
  exit "$code"
}

[ "$(uname -s)" = "Darwin" ] || fail "this script is for a Mac"
if [ "${1:-}" = "logout" ] && [ -n "$PROFILE" ] && [ ! -d "$PROFILE_DIR" ]; then
  # A mistyped name must not report "nothing to sign out" while the real profile stays signed in.
  fail "no profile named $PROFILE has been used on this Mac. Profiles here: $(ls "$APP_DIR/profiles" 2>/dev/null | tr '\n' ' ')"
fi
if [ -n "$LOCAL_SRC" ]; then
  say "bw-health v$VERSION, using the report scripts beside this file ($LOCAL_SRC), not the published ones"
else
  # The script cannot tell which line fetched it (an old line still points at main), so every
  # fetched run opens with the line that pins this version.
  say "bw-health v$VERSION. The line that always runs exactly this version:
    curl -fsSL $RELEASE_URL/bw-health.sh | bash"
fi
export BITWARDENCLI_APPDATA_DIR="$PROFILE_DIR/data"
mkdir -p "$BIN_DIR" "$BITWARDENCLI_APPDATA_DIR"

# --- 1. tools -------------------------------------------------------------------------------
if [ ! -x "$UV" ]; then
  say "Installing uv (runs the report scripts; no admin password needed)"
  curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null || fail "uv install failed"
fi

if [ ! -x "$BW" ]; then
  say "Installing the Bitwarden command-line app"
  if [ "$(uname -m)" = "arm64" ]; then
    asset="bw-macos-arm64-$BW_CLI_VERSION.zip"; want="$BW_CLI_SHA256_ARM64"
  else
    asset="bw-macos-$BW_CLI_VERSION.zip"; want="$BW_CLI_SHA256_X64"
  fi
  url="https://github.com/bitwarden/clients/releases/download/cli-v$BW_CLI_VERSION/$asset"
  tmp="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmp/bw.zip" || fail "download failed: $url"
  [ "$(shasum -a 256 "$tmp/bw.zip" | cut -d' ' -f1)" = "$want" ] || fail "the downloaded Bitwarden app did not match its checksum"
  /usr/bin/unzip -oq "$tmp/bw.zip" -d "$BIN_DIR" || fail "unzip failed"
  rm -rf "$tmp"
  chmod +x "$BW"
fi

[ -n "$LOCAL_SRC" ] || say "Fetching the report scripts"
for f in $FILES; do fetch_file "$f"; done

case "${1:-}" in
  check)
    say "Installed OK"
    "$BW" --version
    "$UV" --version
    exit 0 ;;
  exports)
    stage_exports
    printf '%s\n' ${STAGED[@]+"${STAGED[@]}"}
    exit 0 ;;
  logout)
    status="$(bw_status .status)" || fail "could not read Bitwarden's sign-in status"
    if [ "$status" = "unauthenticated" ]; then
      say "${TAG}Bitwarden was not signed in on this Mac, so there was nothing to sign out."
    else
      sign_out || fail "Bitwarden could not be signed out"
      say "${TAG}Bitwarden is signed out on this Mac."
    fi
    if [ -d "$IMPORT_DIR" ] && [ -n "$(find "$IMPORT_DIR" -type f ! -name .DS_Store | head -1)" ]; then
      say "The Bitwarden Import folder still holds files with plain-text passwords: $IMPORT_DIR
Drag it to the Trash and empty it once the import is done."
    fi
    exit 0 ;;
esac

# --- 2. sign in -----------------------------------------------------------------------------
# `login --raw` and `unlock --raw` both print the session key, so each path asks for the
# master password exactly once.
status="$(bw_status .status)" || fail "could not read Bitwarden's sign-in status"
if [ "$status" = "unauthenticated" ]; then
  if [ -n "$PROFILE" ]; then
    say "Profile $PROFILE: sign in to Bitwarden. Type $PROFILE's email, then the master password (nothing shows while typing), then the two-step code if asked."
  else
    say "Sign in to Bitwarden. Type your email, then your master password (nothing shows while typing), then the two-step code if asked."
  fi
  BW_SESSION="$("$BW" login --raw <"$TTY")" || fail_login
else
  if [ -n "$PROFILE" ]; then
    ACCOUNT="$(account_email)"
    say "Profile $PROFILE is signed in as $ACCOUNT. Unlock that vault: type its master password"
  else
    say "Unlock your vault: type your master password"
  fi
  BW_SESSION="$("$BW" unlock --raw <"$TTY")" || fail_unlock
fi
[ -n "$BW_SESSION" ] || fail "no session key came back from Bitwarden"
export BW_SESSION
trap finish EXIT
if [ -n "$PROFILE" ]; then
  # Shown on every profile run, so a vault signed in under the wrong name is seen before it is used.
  ACCOUNT="$(account_email)"
  say "Profile $PROFILE: this run uses the vault of $ACCOUNT"
fi

# --- 3. health report -----------------------------------------------------------------------
say "Checking every password (this can take a minute)"
export PATH="$BIN_DIR:$PATH"

# --- duplicate cleanup (its own run: `bash -s -- dedupe exact|merge|pick [apply [N]]`) ------------
if [ "${1:-}" = "dedupe" ]; then
  say "Duplicate cleanup: $2${3:+ ($3)}"
  dedupe_args=("$2" --out-dir "$DEDUPE_DIR")
  [ "${3:-}" != "apply" ] || dedupe_args+=(--apply)
  [ -z "${4:-}" ] || dedupe_args+=(--limit "$4")
  "$UV" run --quiet "$APP_DIR/bw_dedupe.py" "${dedupe_args[@]}" </dev/null || fail "duplicate cleanup failed"
  exit 0
fi

# A dated report per run, in this person's own folder. The progress file beside it holds item ids
# and the reasons they were flagged, so the next run can say what was fixed.
mkdir -p "$REPORTS_DIR"
chmod 700 "$REPORTS_DIR"
report="$REPORTS_DIR/$REPORT_NAME $(date '+%Y-%m-%d %H%M%S').html"
"$UV" run --quiet "$APP_DIR/bw_report.py" --html --out "$report" --state "$REPORTS_DIR/progress.json" \
  --twofa-cache "$PROFILE_DIR/2fa-directory.json" || fail "report failed"
chmod 600 "$report"
open "$report"
prune_reports
say "This check only reads your vault. It never merges, deletes or changes anything. Cleaning up duplicates is a separate step you start yourself, and it shows you everything first."

# --- 4. optional import diff --------------------------------------------------------------
stage_exports
if [ "${#STAGED[@]}" -gt 0 ]; then
  say "Comparing ${#STAGED[@]} export(s) with your vault"
  "$UV" run --quiet "$APP_DIR/bw_import_diff.py" "${STAGED[@]}" --out-dir "$IMPORT_DIR" || fail "import diff failed"
  open "$IMPORT_DIR"
  cat <<'EOT'

A "Bitwarden Import" folder just opened in Finder. It is kept out of iCloud on purpose.
Next: at vault.bitwarden.com choose Tools, then Import data, format "Bitwarden (csv)",
then drag "new-for-bitwarden.csv" from that Finder window into the file picker.
Read "conflicts.md" in the same folder. When done, drag the whole folder to the Trash
and empty it: the files inside contain your passwords in plain text.
EOT
  [ -z "$PROFILE" ] || say "These files are $PROFILE's. Import them only into the vault of $ACCOUNT."
  case " ${STAGED[*]} " in *"/apple-passwords-"*) cat <<'EOT'

Passkeys: an Apple csv export carries passwords only, never passkeys (Face ID sign-ins).
Before you ever empty Apple Passwords, open it, look for entries marked "Passkey", and
move each one with the iPhone's Passwords app: the three-dot menu, Export Data to Another
App, select only those entries, choose Bitwarden.
EOT
  ;; esac
elif [ "$MOVED" -gt 0 ]; then
  open "$IMPORT_DIR"
  say "$MOVED old export file(s) were moved into the Bitwarden Import folder that just opened. Drag it to the Trash and empty it: they contain your passwords in plain text."
fi

[ ! -e "$HOME/Desktop/$REPORT_NAME.html" ] || say "An older report, '$REPORT_NAME.html', is still on your Desktop. Reports are no longer saved there: drag it to the Trash."
say "Done. The report is open in your browser. It is kept in $REPORTS_DIR, not on the Desktop. Your vault is locked again."
