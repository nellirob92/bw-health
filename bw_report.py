#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["zxcvbn>=4.4"]
# ///
"""Password health report for a Bitwarden vault.

Flags logins that are exposed in a breach, reused, weak or saved twice; sites that offer two-step
login where no code is saved; logins iPhone AutoFill will not match; passwords unchanged for years;
and notes that look like they hold a password. Reads the vault with `bw list items` and
`bw list folders` (read-only) and never prints a password or the text of a note.

Two network calls, and neither names a site, a username or a person: the breach check sends the
first 5 characters of each password's SHA-1 to Have I Been Pwned, and the two-step check downloads
the whole public 2FA Directory list and matches it here. Needs BW_SESSION from `bw unlock --raw`,
or `--input items.json` for a saved export.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from zxcvbn import zxcvbn

LOGIN_TYPE, NOTE_TYPE = 1, 2
WEAK_MAX_SCORE = 2  # zxcvbn: 0-2 weak, 3 ok, 4 strong
ZXCVBN_MAX_LENGTH = 72  # zxcvbn raises on longer input; a longer password is scored on its first 72 characters
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
TWOFA_URL = "https://api.2fa.directory/v4/all.json"
TWOFA_MAX_AGE_SECONDS = 24 * 3600
USER_AGENT = "bw_report family vault check"
DEFAULT_VAULT_URL = "https://vault.bitwarden.com"
OLD_AFTER = timedelta(days=3 * 365)
RECENTLY_ADDED = timedelta(days=30)

TIER_NAMES = {1: "1 - email, Apple, Google, Microsoft", 2: "2 - money", 3: "3 - phone, utilities, insurance, health",
              4: "4 - gaming and social", 5: "5 - everything else"}
LAST_TIER = 5

# The reasons an item can be flagged, as kept in the progress file.
EXPOSED, REUSED, WEAK, DUPLICATE, TWOFA, AUTOFILL, OLD, NOTES = (
    "exposed", "reused", "weak", "duplicate", "two-step", "autofill", "old", "notes")

# Only values of these shapes are put into a link.
SAFE_HOST = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
SAFE_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
SAFE_VAULT_URL = re.compile(r"https?://[a-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9./-]*)?")

NOTE_KEYWORD = re.compile(
    r"\b(password|passwd|passphrase|passcode|pwd|pw|pin|security answer|secret answer)\b\s*[:=]\s*\S", re.IGNORECASE)
NOTE_PAIR = re.compile(r"[^\s:/]{3,}:[^\s:/]{6,}")


def suffixes(host: str) -> list[str]:
    """The host and each parent with at least two labels, longest first: a.b.example.com, b.example.com, example.com."""
    parts = host.lower().split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


@dataclass
class FixOrder:
    """fix_order.txt: which sites, and which Bitwarden folders, are fixed first."""
    domains: dict[str, int]
    folders: dict[str, int]  # lower-case folder name -> tier

    def listed(self, host: str) -> str | None:
        return next((s for s in suffixes(host) if s in self.domains), None)

    def tier(self, hosts: list[str], folder: str | None) -> int:
        """A folder line wins. Otherwise the best tier among the login's addresses, each matched on the listed
        domain it equals or sits under, so mail.google.com is google.com and gmail.example.com is nothing."""
        if folder is not None and folder.strip().lower() in self.folders:
            return self.folders[folder.strip().lower()]
        return min((self.domains[d] for h in hosts if (d := self.listed(h))), default=LAST_TIER)

    def site(self, host: str) -> str:
        """The listed domain a host belongs to, or the host itself: accounts.google.com is google.com."""
        return self.listed(host) or host.lower()


def load_fix_order(path: Path) -> FixOrder:
    order = FixOrder({}, {})
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tier, _, rest = line.partition(" ")
        rest = rest.strip()
        if tier not in {str(t) for t in TIER_NAMES} or not rest:
            sys.exit(f"{path} line {n}: expected a tier from 1 to {LAST_TIER}, a space, then a domain or 'folder: name'")
        if rest.lower().startswith("folder:"):
            table, key = order.folders, rest[len("folder:"):].strip().lower()
            if not key:
                sys.exit(f"{path} line {n}: 'folder:' needs a folder name after it")
        else:
            table, key = order.domains, rest.lower()
            if not SAFE_HOST.fullmatch(key):
                sys.exit(f"{path} line {n}: '{rest}' is not a domain like example.com")
        if table.setdefault(key, int(tier)) != int(tier):
            sys.exit(f"{path} line {n}: '{rest}' is listed twice with different tiers")
    return order


@dataclass
class TwoFa:
    """The 2FA Directory list, reduced to the domains that offer two-step login."""
    offering: set[str]
    under: set[str]  # each offering domain and its parents, so a login saved on the parent site still matches

    def offers(self, site: str) -> bool:
        return site in self.under or any(s in self.offering for s in suffixes(site))


def parse_twofa(raw: str) -> TwoFa:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("the list is not the shape this script knows")
    offering = {d.lower() for d, entry in data.items() if isinstance(entry, dict) and entry.get("methods")}
    return TwoFa(offering, {s for d in offering for s in suffixes(d)})


def load_twofa(file: str | None, cache: str | None) -> tuple[TwoFa | None, str]:
    """(the list, "") or (None, why it could not be had). The download is one GET of the whole public list: nothing
    about the vault is sent. With a cache path, a copy younger than a day is used instead of downloading again."""
    try:
        if file:
            return parse_twofa(Path(file).read_text(encoding="utf-8")), ""
        cached = Path(cache) if cache else None
        if cached and cached.exists() and time.time() - cached.stat().st_mtime < TWOFA_MAX_AGE_SECONDS:
            return parse_twofa(cached.read_text(encoding="utf-8")), ""
        req = urllib.request.Request(TWOFA_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        parsed = parse_twofa(raw)
        if cached:
            tmp = cached.with_name(cached.name + ".new")
            tmp.write_text(raw, encoding="utf-8")
            tmp.replace(cached)
        return parsed, ""
    except (OSError, ValueError) as err:  # no network, a refused download, or a list that is not what it was
        print(f"The two-step check was skipped: the list of sites could not be used ({err}).", file=sys.stderr)
        return None, "the list of sites could not be downloaded"


def plain(text: str) -> str:
    """Vault text that is safe in a report line: it can never form a link."""
    return text.replace("](", "] (")


@dataclass
class Login:
    item_id: str
    name: str
    username: str
    host: str               # the first address's host: what the label and the site links use
    hosts: list[str]
    uris: list[str]
    password: str
    in_trash: bool
    tier: int
    has_totp: bool
    changed: datetime | None  # when Bitwarden last saw the password change
    created: datetime | None

    @property
    def label(self) -> str:
        who = f" ({self.username})" if self.username else ""
        where = f" - {self.host}" if self.host and self.host not in self.name else ""
        return plain(f"{self.name}{who}{where}")

    @property
    def account(self) -> str:
        """Same site + username (case-insensitive) is one account; a login missing either stands alone."""
        if self.host and self.username:
            return f"{self.host}|{self.username.lower()}"
        return f"item:{self.item_id}"


@dataclass
class NoteHit:
    item_id: str
    name: str
    kind: str    # "secure note" or "login"
    reason: str


@dataclass
class Report:
    total: int = 0
    trashed: int = 0
    no_password: int = 0
    reused: dict[str, list[Login]] = field(default_factory=dict)   # key = sha1 of password
    weak: list[tuple[Login, int, str]] = field(default_factory=list)
    exposed: list[tuple[Login, int]] = field(default_factory=list)
    duplicates: dict[str, list[Login]] = field(default_factory=dict)
    hibp_checked: bool = False
    twofa: list[Login] = field(default_factory=list)
    twofa_skipped: str = ""    # why the two-step check did not run, or "" when it did
    autofill: list[tuple[Login, str]] = field(default_factory=list)
    old: list[tuple[Login, datetime, str]] = field(default_factory=list)
    recently_added: int = 0
    notes: list[NoteHit] = field(default_factory=list)

    def flags(self) -> dict[str, set[str]]:
        """Item id -> the reasons it is flagged. Ids and reason names only: this is all the progress file holds."""
        out: dict[str, set[str]] = defaultdict(set)
        for reason, logins in (
                (EXPOSED, [l for l, _ in self.exposed]), (REUSED, [l for ls in self.reused.values() for l in ls]),
                (WEAK, [l for l, _, _ in self.weak]), (DUPLICATE, [l for ls in self.duplicates.values() for l in ls]),
                (TWOFA, self.twofa), (AUTOFILL, [l for l, _ in self.autofill]), (OLD, [l for l, _, _ in self.old])):
            for l in logins:
                out[l.item_id].add(reason)
        for hit in self.notes:
            out[hit.item_id].add(NOTES)
        return dict(out)

    def checks(self) -> set[str]:
        """The checks that ran, so a check that was skipped is never read as everything being fixed."""
        ran = {REUSED, WEAK, DUPLICATE, AUTOFILL, OLD, NOTES}
        if self.hibp_checked:
            ran.add(EXPOSED)
        if not self.twofa_skipped:
            ran.add(TWOFA)
        return ran


@dataclass
class Progress:
    since: str | None = None   # the date of the check-up before this one, None when there was none
    fixed: int = 0
    new: set[str] = field(default_factory=set)   # item ids flagged now that were not flagged then


def run_bw(*args: str) -> str:
    """Run a read-only bw command and return stdout. Fails loud on any error."""
    env = dict(os.environ)
    try:
        done = subprocess.run(["bw", *args], capture_output=True, text=True, env=env, check=False)
    except FileNotFoundError:
        sys.exit("bw CLI not found. Install it: brew install bitwarden-cli")
    if done.returncode != 0:
        sys.exit(f"bw {' '.join(args)} failed:\n{done.stderr.strip() or done.stdout.strip()}")
    return done.stdout


def load_vault(args: argparse.Namespace) -> tuple[list[dict], dict[str, str], str]:
    """(items, folder id -> name, web vault address)."""
    if args.input:
        raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
        folders = json.loads(Path(args.folders).read_text(encoding="utf-8")) if args.folders else []
        server = args.vault_url
    else:
        if not os.environ.get("BW_SESSION"):
            sys.exit('Vault is locked. Run:  export BW_SESSION="$(bw unlock --raw)"  then try again.')
        status = json.loads(run_bw("status"))
        if status.get("status") != "unlocked":
            sys.exit(f"bw status is '{status.get('status')}'. Run: bw login, then export BW_SESSION=\"$(bw unlock --raw)\"")
        run_bw("sync")
        raw = run_bw("list", "items")
        folders = json.loads(run_bw("list", "folders"))
        server = status.get("serverUrl") or DEFAULT_VAULT_URL  # bw reports none for the default (US) server
    names = {f["id"]: f.get("name") or "" for f in folders if f.get("id")}
    return json.loads(raw), names, server.rstrip("/")


def uris_of(item: dict) -> list[str]:
    return [uri for u in (item.get("login") or {}).get("uris") or [] if (uri := ((u or {}).get("uri") or "").strip())]


def host_from(uri: str) -> str:
    try:
        parsed = urlparse(uri if "://" in uri else f"https://{uri}")
    except ValueError:  # real vaults hold malformed URLs (an unclosed IPv6 bracket); one must not stop the report
        return uri.strip().lower()
    host = parsed.hostname or uri
    return host[4:] if host.startswith("www.") else host


def when(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def to_logins(items: list[dict], order: FixOrder, folders: dict[str, str]) -> tuple[list[Login], int]:
    logins, no_password = [], 0
    for it in items:
        if it.get("type") != LOGIN_TYPE:
            continue
        login = it.get("login") or {}
        pw = login.get("password") or ""
        if not pw:
            no_password += 1
            continue
        uris = uris_of(it)
        hosts = [host_from(u) for u in uris]
        logins.append(Login(
            item_id=it["id"],
            name=it.get("name") or "(no name)",
            username=login.get("username") or "",
            host=hosts[0] if hosts else "",
            hosts=hosts,
            uris=uris,
            password=pw,
            in_trash=bool(it.get("deletedDate")),
            tier=order.tier(hosts, folders.get(it.get("folderId"))),
            has_totp=bool(login.get("totp")),
            changed=when(login.get("passwordRevisionDate")),
            created=when(it.get("creationDate")),
        ))
    return logins, no_password


def sha1_upper(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def hibp_counts(hashes: set[str]) -> dict[str, int]:
    """Breach count per full SHA-1, via the k-anonymity range API. One request per 5-char prefix."""
    by_prefix: dict[str, set[str]] = defaultdict(set)
    for h in hashes:
        by_prefix[h[:5]].add(h)
    found: dict[str, int] = {}
    for prefix, full in sorted(by_prefix.items()):
        req = urllib.request.Request(
            HIBP_RANGE_URL + prefix,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            suffix, _, count = line.strip().partition(":")
            full_hash = prefix + suffix
            if full_hash in full and int(count) > 0:
                found[full_hash] = int(count)
    return found


def autofill_problem(l: Login) -> str | None:
    if not l.uris:
        return "no web address saved"
    if all(u.lower().startswith("http://") for u in l.uris):
        return "only an http:// address saved"
    return None


def note_reason(text: str) -> str | None:
    """Why a note looks like it holds a password, or None. Only the reason is ever reported, never the line."""
    for line in text.splitlines():
        if NOTE_KEYWORD.search(line):
            return "a line that looks like a saved password or PIN"
        if NOTE_PAIR.fullmatch(line.strip()):
            return "a line shaped like username:password"
    return None


def build(items: list[dict], order: FixOrder, folders: dict[str, str], check_hibp: bool,
          twofa: TwoFa | None, twofa_skipped: str, now: datetime) -> Report:
    rep = Report(twofa_skipped=twofa_skipped)
    logins, rep.no_password = to_logins(items, order, folders)
    rep.total = len(logins)
    rep.trashed = sum(1 for l in logins if l.in_trash)
    live = [l for l in logins if not l.in_trash]

    by_hash: dict[str, list[Login]] = defaultdict(list)
    for l in live:
        by_hash[sha1_upper(l.password)].append(l)
    for h, ls in by_hash.items():
        first: dict[str, Login] = {}
        for l in ls:
            first.setdefault(l.account, l)
        if len(first) > 1:
            rep.reused[h] = list(first.values())

    scored: dict[str, tuple[int, str]] = {}
    for h, ls in by_hash.items():
        result = zxcvbn(ls[0].password[:ZXCVBN_MAX_LENGTH], user_inputs=[ls[0].username, ls[0].host])
        warning = result["feedback"]["warning"] or ""
        scored[h] = (result["score"], warning)
    for l in live:
        score, warning = scored[sha1_upper(l.password)]
        if score <= WEAK_MAX_SCORE:
            rep.weak.append((l, score, warning))

    if check_hibp:
        counts = hibp_counts(set(by_hash))
        for h, n in counts.items():
            for l in by_hash[h]:
                rep.exposed.append((l, n))
        rep.hibp_checked = True

    by_account: dict[str, list[Login]] = defaultdict(list)
    for l in live:
        if l.host and l.username:
            by_account[f"{l.host}|{l.username.lower()}"].append(l)
    rep.duplicates = {k: ls for k, ls in by_account.items() if len(ls) > 1}

    for l in live:
        if twofa and not l.has_totp and any(twofa.offers(order.site(h)) for h in l.hosts):
            rep.twofa.append(l)
        problem = autofill_problem(l)
        if problem:
            rep.autofill.append((l, problem))
        if l.created and now - l.created < RECENTLY_ADDED:
            rep.recently_added += 1  # an import or a new entry: its dates say nothing about the password's age yet
        elif (since := l.changed or l.created) and now - since >= OLD_AFTER:
            rep.old.append((l, since, "last changed" if l.changed else "saved"))

    for it in items:
        if it.get("deletedDate") or it.get("type") not in (LOGIN_TYPE, NOTE_TYPE):
            continue
        reason = note_reason(it.get("notes") or "")
        if reason:
            rep.notes.append(NoteHit(it["id"], it.get("name") or "(no name)",
                                     "secure note" if it["type"] == NOTE_TYPE else "login", reason))
    return rep


def read_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    if not (isinstance(state, dict) and isinstance(state.get("date"), str) and isinstance(state.get("checks"), list)
            and isinstance(state.get("flagged"), dict)):
        sys.exit(f"{path} is not a progress file this script wrote. Move it away and run again.")
    return state


def write_state(path: Path, rep: Report, today: str) -> None:
    """Item ids and reason names, nothing else: no name, no site, no username, no password, no hash."""
    state = {"version": 1, "date": today, "checks": sorted(rep.checks()),
             "flagged": {item_id: sorted(reasons) for item_id, reasons in sorted(rep.flags().items())}}
    tmp = path.with_name(path.name + ".new")
    tmp.write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def compare(previous: dict | None, rep: Report) -> Progress:
    """Against the check-up before this one, on the checks that ran both times."""
    if previous is None:
        return Progress()
    common = set(previous["checks"]) & rep.checks()
    before = {item_id for item_id, reasons in previous["flagged"].items() if set(reasons) & common}
    now = {item_id for item_id, reasons in rep.flags().items() if reasons & common}
    return Progress(previous["date"], len(before - now), now - before)


def md_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    out += ["| " + " | ".join(c.replace("|", "/") for c in r) + " |" for r in rows]
    return "\n".join(out)


def render(rep: Report, progress: Progress, vault_url: str, today: str) -> str:
    vault = vault_url if SAFE_VAULT_URL.fullmatch(vault_url) else ""
    exposed_ids = {l.account for l, _ in rep.exposed}
    reused_ids = {l.account for ls in rep.reused.values() for l in ls}
    weak_ids = {l.account for l, _, _ in rep.weak}
    at_risk: dict[str, Login] = {}
    for l in [l for ls in rep.reused.values() for l in ls] + [l for l, _, _ in rep.weak] + [l for l, _ in rep.exposed]:
        at_risk.setdefault(l.account, l)

    def marked(text: str, item_id: str) -> str:
        return f"{text} **NEW**" if item_id in progress.new else text

    def item_link(item_id: str) -> list[str]:
        return [f"[Open in Bitwarden]({vault}/#/vault?itemId={item_id})"] if vault and SAFE_ID.fullmatch(item_id) else []

    def links(l: Login, change_password: bool = False) -> str:
        """Links are built from the saved address only; no site is contacted to see whether a page exists."""
        out = []
        if SAFE_HOST.fullmatch(l.host):
            if change_password:
                out.append(f"[Change password](https://{l.host}/.well-known/change-password)")
            out.append(f"[Site](https://{l.host}/)")
        return ", ".join(out + item_link(l.item_id))

    flagged = rep.flags()
    lines = ["# Bitwarden password health report", "", f"Check-up of {today}.", ""]
    if progress.since is None:
        lines.append(f"**First check-up of this vault on this Mac: {len(flagged)} flagged.** The next one will show what changed.")
    else:
        new = f" {len(progress.new)} new since then, marked NEW." if progress.new else ""
        lines.append(f"**{progress.fixed} fixed since {progress.since}, {len(flagged)} left.**{new}")
    lines.append("")
    lines.append(md_table(
        ["Check", "Count"],
        [["Logins with a password", str(rep.total - rep.trashed)],
         ["In trash (ignored, empty it)", str(rep.trashed)],
         ["Logins with no password", str(rep.no_password)],
         ["Exposed in a breach", str(len(rep.exposed)) if rep.hibp_checked else "not checked (--no-hibp)"],
         ["Reused (accounts sharing a password)", str(len(reused_ids))],
         ["Distinct passwords reused", str(len(rep.reused))],
         ["Weak", str(len(rep.weak))],
         ["Duplicate entries (same site + username)", str(sum(len(v) for v in rep.duplicates.values()))],
         ["**Logins that need a new password**", f"**{len(at_risk)}**"],
         ["Sites that offer two-step login, no code saved here",
          f"not checked ({rep.twofa_skipped})" if rep.twofa_skipped else str(len(rep.twofa))],
         ["AutoFill problems", str(len(rep.autofill))],
         ["Passwords unchanged for 3+ years", str(len(rep.old))],
         ["Notes that may hold a password", str(len(rep.notes))]],
    ))
    lines.append("")

    lines += ["## Fix in this order", ""]
    if not at_risk:
        lines.append("Nothing. Every live password is unique, strong and unseen in a breach.")
    else:
        lines += ["\"Change password\" opens the site's own change-password page where it has one; if that page is "
                  "missing, use \"Site\" and look under account settings.", ""]
        rows = []
        for l in sorted(at_risk.values(), key=lambda x: (x.tier, 0 if x.account in exposed_ids else 1, x.name.lower())):
            why = ", ".join(w for w, hit in (("exposed", l.account in exposed_ids),
                                             ("reused", l.account in reused_ids),
                                             ("weak", l.account in weak_ids)) if hit)
            rows.append([TIER_NAMES[l.tier], marked(l.label, l.item_id), why, links(l, change_password=True)])
        lines.append(md_table(["Priority", "Login", "Why", "Links"], rows))
    lines.append("")

    if rep.hibp_checked:
        lines += ["## Exposed in a breach", ""]
        if rep.exposed:
            lines.append("Change these today. The count is how many times that exact password appears in public breach dumps.")
            lines.append("")
            lines.append(md_table(["Login", "Seen in breaches"],
                                  [[l.label, f"{n:,}"] for l, n in sorted(rep.exposed, key=lambda x: -x[1])]))
        else:
            lines.append("None.")
        lines.append("")

    lines += ["## Reused passwords", ""]
    if rep.reused:
        for n, (h, ls) in enumerate(sorted(rep.reused.items(), key=lambda kv: -len(kv[1])), start=1):
            lines.append(f"**Password group {n}: used {len(ls)} times**")
            lines += [f"- {l.label}" for l in sorted(ls, key=lambda x: x.name.lower())]
            lines.append("")
    else:
        lines += ["None.", ""]

    lines += ["## Weak passwords", ""]
    if rep.weak:
        lines.append(md_table(["Login", "Score (0-4)", "Why"],
                              [[l.label, str(s), w or "short or predictable"]
                               for l, s, w in sorted(rep.weak, key=lambda x: (x[1], x[0].name.lower()))]))
    else:
        lines.append("None.")
    lines.append("")

    lines += ["## Duplicate entries", ""]
    if rep.duplicates:
        lines.append("Same site and username saved more than once, usually one from Apple and one from Chrome. Keep the newest, delete the rest, then empty the trash.")
        lines.append("")
        for key, ls in sorted(rep.duplicates.items()):
            host, user = key.split("|", 1)
            lines.append(f"- {plain(host)} ({plain(user)}): {len(ls)} copies")
    else:
        lines.append("None.")
    lines.append("")

    lines += ["## Two-step login", ""]
    if rep.twofa_skipped:
        lines.append(f"Not checked this time: {rep.twofa_skipped}.")
    elif rep.twofa:
        lines += ["For each login below: this site offers two-step login; check it's on. No one-time code is saved in the "
                  "Bitwarden entry, and the entry cannot show whether two-step login is already on at the site (a text "
                  "message or another app would not show here).", ""]
        lines.append(md_table(["Priority", "Login", "Links"],
                              [[TIER_NAMES[l.tier], marked(l.label, l.item_id), links(l)]
                               for l in sorted(rep.twofa, key=lambda x: (x.tier, x.name.lower()))]))
    else:
        lines.append("None.")
    if not rep.twofa_skipped:
        lines += ["", "_Data sourced from [2FA Directory](https://2fa.directory/) by 2factorauth._"]
    lines.append("")

    lines += ["## AutoFill problems", ""]
    if rep.autofill:
        lines += ["iPhone AutoFill matches a login by its web address, so these will not be offered reliably. Add the "
                  "site's https:// address to the entry.", ""]
        lines.append(md_table(["Login", "Problem", "Links"],
                              [[marked(l.label, l.item_id), problem, links(l)]
                               for l, problem in sorted(rep.autofill, key=lambda x: x[0].name.lower())]))
    else:
        lines.append("None.")
    lines.append("")

    lines += ["## Passwords unchanged for 3+ years", ""]
    lines += ["Importing passwords resets these dates, so right after an import nothing is old yet: this list only means "
              "something on later check-ups.", ""]
    if rep.recently_added:
        lines += [f"{rep.recently_added} login(s) were added in the last 30 days (an import, for example) and are not "
                  "judged here yet.", ""]
    if rep.old:
        lines.append(md_table(["Priority", "Login", "Since", "Links"],
                              [[TIER_NAMES[l.tier], marked(l.label, l.item_id), f"{kind} {since.astimezone():%Y-%m-%d}",
                                links(l, change_password=True)]
                               for l, since, kind in sorted(rep.old, key=lambda x: (x[0].tier, x[1]))]))
    else:
        lines.append("None.")
    lines.append("")

    lines += ["## Notes that may hold a password", ""]
    if rep.notes:
        lines += ["A password kept in a note is not checked, not filled in and easy to forget. Move it into the entry's "
                  "password field, or a hidden custom field. The note's text is never shown here.", ""]
        lines.append(md_table(["Item", "Kind", "Why", "Links"],
                              [[marked(plain(hit.name), hit.item_id), hit.kind, hit.reason, ", ".join(item_link(hit.item_id))]
                               for hit in sorted(rep.notes, key=lambda x: x.name.lower())]))
    else:
        lines.append("None.")
    lines.append("")

    lines += ["## Your Bitwarden account", ""]
    lines.append("This check-up cannot see whether your Bitwarden email address is verified, or whether two-step login "
                 "is turned on for Bitwarden itself. Please check both:")
    if vault:
        lines += [f"- [Account settings]({vault}/#/settings/account): a notice at the top asks you to verify your email if it is not verified yet.",
                  f"- [Two-step login]({vault}/#/settings/security/two-factor): Settings, then Security, then Two-step login."]
    else:
        lines += ["- In the Bitwarden web vault, open Settings, then My account: a notice asks you to verify your email if it is not verified yet.",
                  "- In the Bitwarden web vault, open Settings, then Security, then Two-step login."]
    lines.append("")
    lines.append("_Passwords themselves are never shown in this report. Breach check: Have I Been Pwned range API (k-anonymity)._")
    return "\n".join(lines)


HTML_HEAD = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitwarden password health report</title><style>
body{font:16px/1.5 -apple-system,Helvetica,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.6rem}h2{font-size:1.2rem;margin-top:2rem;border-bottom:2px solid #ddd;padding-bottom:.25rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f3f3f3}tr:nth-child(even) td{background:#fafafa}li{margin:.15rem 0}a{text-decoration:underline}
</style></head><body>
"""


def inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\[([^\]\[]+)\]\((https?://[^\s()\"]+)\)", r'<a href="\2" rel="noreferrer noopener">\1</a>', text)
    return re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"<em>\1</em>", text)


def to_html(md: str) -> str:
    """The subset of Markdown this report emits: headings, pipe tables, bullets, bold, italics, links."""
    out, table, in_list = [HTML_HEAD], [], False

    def flush_table() -> None:
        if not table:
            return
        head, body = table[0], table[2:]
        out.append("<table><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr>")
        out.extend("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>" for row in body)
        out.append("</table>")
        table.clear()

    for line in md.splitlines():
        if line.startswith("|"):
            table.append([c.strip() for c in line.strip().strip("|").split("|")])
            continue
        flush_table()
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(line[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    flush_table()
    if in_list:
        out.append("</ul>")
    out.append("</body></html>")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--input", help="JSON array from `bw list items` (file path or - for stdin) instead of calling bw")
    ap.add_argument("--folders", help="with --input: JSON array from `bw list folders`, for the folder lines of the fix order")
    ap.add_argument("--vault-url", default=DEFAULT_VAULT_URL, help="with --input: the web vault the links open (bw's server otherwise)")
    ap.add_argument("--out", help="write the report here instead of stdout")
    ap.add_argument("--html", action="store_true", help="emit HTML instead of Markdown")
    ap.add_argument("--no-hibp", action="store_true", help="skip the Have I Been Pwned breach check")
    ap.add_argument("--no-twofa", action="store_true", help="skip the two-step login check")
    ap.add_argument("--twofa-file", help="a saved copy of the 2FA Directory list (v4 all.json) instead of downloading it")
    ap.add_argument("--twofa-cache", help="keep the downloaded 2FA Directory list here and reuse it for a day")
    ap.add_argument("--fix-order", default=str(Path(__file__).with_name("fix_order.txt")),
                    help="the fix-order list (default: fix_order.txt beside this script)")
    ap.add_argument("--state", help="progress file: compared with the last check-up, then rewritten (item ids and reasons only)")
    args = ap.parse_args()

    order = load_fix_order(Path(args.fix_order))
    items, folders, vault_url = load_vault(args)
    if args.no_twofa:
        twofa, skipped = None, "--no-twofa"
    else:
        twofa, skipped = load_twofa(args.twofa_file, args.twofa_cache)
    now = datetime.now(timezone.utc)
    today = f"{now.astimezone():%Y-%m-%d}"
    rep = build(items, order, folders, not args.no_hibp, twofa, skipped, now)
    state = Path(args.state) if args.state else None
    progress = compare(read_state(state) if state else None, rep)
    report = render(rep, progress, vault_url, today)
    if args.html:
        report = to_html(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"wrote {args.out}")
    else:
        print(report)
    if state:
        write_state(state, rep, today)


if __name__ == "__main__":
    main()
