#!/bin/bash
# One-line Bitwarden password check-up for a Mac. Read-only on the vault.
#   curl -fsSL <BASE_URL>/bw-health.sh | bash                          # full run: report, then export staging
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- check              # install only
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- dedupe exact|merge|pick # duplicate cleanup preview (read-only)
#   curl -fsSL <BASE_URL>/bw-health.sh | bash -s -- dedupe merge apply [N]   # act on it, after a typed confirmation
#   bash bw-health.sh exports                                          # stage Downloads exports only
# Only the dedupe step ever changes the vault; see README.md.

set -euo pipefail

BASE_URL="${BW_HEALTH_BASE_URL:-https://raw.githubusercontent.com/nellirob92/bw-health/main}"
APP_DIR="$HOME/Library/Application Support/bw-health"
BIN_DIR="$APP_DIR/bin"
REPORT_DIR="$HOME/Desktop"
# Under Library, never Desktop: iCloud's Desktop sync would upload the plain-text exports.
IMPORT_DIR="$APP_DIR/Bitwarden Import"
DEDUPE_DIR="$APP_DIR/Dedupe Plan"
UV="$HOME/.local/bin/uv"
BW="$BIN_DIR/bw"
# Pinned: the download is a release file, not a GitHub API lookup (the API rate-limits shared IPs).
# To bump, take both hashes from the cli-v<version> release assets' sha256 digests.
BW_CLI_VERSION="2026.10.0"
BW_CLI_SHA256_ARM64="062c880508678b8d936ab2522a3a1e92d60f52b5c534e71406e9b47329e95207"
BW_CLI_SHA256_X64="39602a597ca63127c22ee3844546f3fe06079e4f67be7b9a7ea4e30ede8721d0"

say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\nSomething went wrong: %s\nSend a screenshot of this window to the person who sent you this line.\n' "$*" >&2; exit 1; }

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
  local attempt f kind mtime cutoff stale_note fresh answer
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
    printf 'Press Return when the export is done, or type skip and Return: '
    read -r answer <"$TTY"
    [ "$answer" != "skip" ] || { say "Skipping the import step"; return 0; }
  done
  while IFS="$(printf '\t')" read -r mtime kind f; do
    move_export "$f" "$kind" "$mtime"
    STAGED+=("$LAST_DEST")
  done <<<"$(printf '%s' "$fresh" | sort -rn)"
}

[ "$(uname -s)" = "Darwin" ] || fail "this script is for a Mac"
export BITWARDENCLI_APPDATA_DIR="$APP_DIR/data"
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

say "Fetching the report scripts"
for f in bw_report.py bw_import_diff.py bw_dedupe.py; do
  curl -fsSL "$BASE_URL/$f" -o "$APP_DIR/$f" || fail "could not download $f"
done

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
  dedupe)
    case "${2:-}" in exact|merge|pick) ;; *) fail "use: dedupe exact, dedupe merge or dedupe pick. Add apply to act, then a number to limit how many groups." ;; esac
    case "${3:-}" in ""|apply) ;; *) fail "after the stage, the only word allowed is apply" ;; esac
    [ -z "${4:-}" ] || { [ "${3:-}" = apply ] && [[ "$4" =~ ^[1-9][0-9]*$ ]]; } || fail "a limit goes after apply and is a whole number, 1 or more"
    [ -z "${5:-}" ] || fail "nothing is allowed after the limit" ;;
esac

# --- 2. sign in -----------------------------------------------------------------------------
# `login --raw` and `unlock --raw` both print the session key, so each path asks for the
# master password exactly once.
status="$("$BW" status | /usr/bin/jq -r .status)"
if [ "$status" = "unauthenticated" ]; then
  say "Sign in to Bitwarden. Type your email, then your master password (nothing shows while typing), then the two-step code if asked."
  BW_SESSION="$("$BW" login --raw <"$TTY")" || fail_login
else
  say "Unlock your vault: type your master password"
  BW_SESSION="$("$BW" unlock --raw <"$TTY")" || fail_unlock
fi
[ -n "$BW_SESSION" ] || fail "no session key came back from Bitwarden"
export BW_SESSION
trap '"$BW" lock >/dev/null 2>&1 || true' EXIT

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

report="$REPORT_DIR/Bitwarden Report.html"
"$UV" run --quiet "$APP_DIR/bw_report.py" --html --out "$report" || fail "report failed"
open "$report"
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

say "Done. The report is on your Desktop as 'Bitwarden Report.html'. Your vault is locked again."
