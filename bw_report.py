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

The report is one self-contained HTML page, grouped by site: one row per website and username,
however many copies or addresses it has. A site is a registrable domain from the public suffix list
(bw_dedupe.py reads it, and the duplicate cleanup uses the same groups). A second page, the summary,
holds counts only, to share with family.

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
import math
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

import bw_dedupe as dd

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
FIX_FIRST = 10

TIER_NAMES = {1: "Email & main accounts", 2: "Money & shopping", 3: "Phone, utilities, insurance & health",
              4: "Gaming & social", 5: "Everything else"}
LAST_TIER = 5

# The reasons an item can be flagged, as kept in the progress file.
EXPOSED, REUSED, WEAK, DUPLICATE, TWOFA, AUTOFILL, OLD, NOTES, MASKED = (
    "exposed", "reused", "weak", "duplicate", "two-step", "autofill", "old", "notes", "masked")
# Worst first, the order chips are shown in. A site's urgency (Site.urgency) ranks the fix list.
SEVERITY = [EXPOSED, REUSED, WEAK, OLD, DUPLICATE, MASKED, TWOFA, AUTOFILL]
NEEDS_NEW_PASSWORD = {EXPOSED, REUSED, WEAK}
CHIP_WORDS = {EXPOSED: "Exposed", REUSED: "Reused", WEAK: "Weak", OLD: "Old", DUPLICATE: "Duplicate", MASKED: "Masked",
              TWOFA: "Two-step", AUTOFILL: "AutoFill", "new": "NEW"}

# How a login was matched to the 2FA Directory list: its own address is listed, or only a related one is.
SUPPORTS, LIKELY = "supports two-step", "likely supports two-step"

# Only values of these shapes are put into a link.
SAFE_HOST = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
SAFE_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
SAFE_VAULT_URL = re.compile(r"https?://[a-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9./-]*)?")
SAFE_PASTE_LINE = re.compile(r"curl -fsSL https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/v[0-9]+\.[0-9]+\.[0-9]+"
                             r"/bw-health\.sh \| bash -s --")
SAFE_USER = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")

NOTE_KEYWORD = re.compile(
    r"\b(password|passwd|passphrase|passcode|pwd|pw|pin|security answer|secret answer)\b\s*[:=]\s*\S", re.IGNORECASE)
NOTE_PAIR = re.compile(r"[^\s:/]{3,}:[^\s:/]{6,}")


def suffixes(host: str) -> list[str]:
    """The host and each parent with at least two labels, longest first: a.b.example.com, b.example.com, example.com."""
    parts = host.lower().split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


@dataclass
class FixOrder:
    """fix_order.txt: which sites, and which Bitwarden folders, are fixed first. The one place the kinds of site are decided."""
    domains: dict[str, int]
    folders: dict[str, int]  # lower-case folder name -> tier
    endings: dict[str, int]  # a top-level ending such as "gov" -> tier; a domain line wins over it

    def listed(self, host: str) -> str | None:
        return next((s for s in suffixes(host) if s in self.domains), None)

    def tier(self, hosts: list[str], folder: str | None) -> int:
        """A folder line wins. Otherwise the best tier among the login's addresses, each matched on the listed
        domain it equals or sits under, so mail.google.com is google.com and gmail.example.com is nothing."""
        if folder is not None and folder.strip().lower() in self.folders:
            return self.folders[folder.strip().lower()]
        listed = [self.domains[d] for h in hosts if (d := self.listed(h))]
        ending = [self.endings[e] for h in hosts if (e := h.lower().rpartition(".")[2]) in self.endings and "." in h]
        return min(listed or ending or [LAST_TIER])

    def site(self, host: str) -> str:
        """The listed domain a host belongs to, or the host itself: accounts.google.com is google.com."""
        return self.listed(host) or host.lower()


def load_fix_order(path: Path) -> FixOrder:
    order = FixOrder({}, {}, {})
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tier, _, rest = line.partition(" ")
        rest = rest.strip()
        if tier not in {str(t) for t in TIER_NAMES} or not rest:
            sys.exit(f"{path} line {n}: expected a tier from 1 to {LAST_TIER}, a space, then a domain, an ending like .gov or 'folder: name'")
        if rest.lower().startswith("folder:"):
            table, key = order.folders, rest[len("folder:"):].strip().lower()
            if not key:
                sys.exit(f"{path} line {n}: 'folder:' needs a folder name after it")
        elif rest.startswith("."):
            table, key = order.endings, rest[1:].lower()
            if not re.fullmatch(r"[a-z]{2,}", key):
                sys.exit(f"{path} line {n}: '{rest}' is not a top-level ending like .gov")
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

    def related(self, name: str) -> bool:
        """Is this address above a listed one, or at or below one?"""
        return name in self.under or any(s in self.offering for s in suffixes(name))

    def match(self, host: str, site: str) -> str | None:
        """How an address ties to the list. SUPPORTS: the address itself is listed. LIKELY: only a related address
        is, one above or below it, or another address of the same site (site is its fix_order.txt domain). None:
        nothing ties it to the list, and it is not flagged."""
        if host.lower() in self.offering:
            return SUPPORTS
        return LIKELY if self.related(host.lower()) or self.related(site) else None


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
        print(f"The two-step check was not run: the list of sites could not be used ({err}).", file=sys.stderr)
        return None, "the list of sites could not be downloaded"


@dataclass
class Login:
    item_id: str
    name: str
    username: str
    host: str               # the first address's host, without www.: what the strength check is told
    hosts: list[str]
    uris: list[str]
    site: str               # the site the login belongs to (bw_dedupe.site_of), "" with no address
    key: str                # site + username, or the item alone when either is missing: one row of the report
    secure: bool            # an https:// or bare address is saved, so a change-password link may be offered
    password: str
    in_trash: bool
    tier: int
    has_totp: bool
    changed: datetime | None  # when Bitwarden last saw the password change
    created: datetime | None
    revised: str            # the item's last edit, as bw writes it
    has_passkey: bool
    masked_copy: bool       # a masked username matched to one unmasked username on the site: shown on that account's row


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
    breaches: dict[str, int] = field(default_factory=dict)          # sha1 -> times seen in breaches
    dupes: list[dd.Group] = field(default_factory=list)             # the duplicate cleanup's own groups
    safe_merge: int = 0                                             # of those, how many `dedupe merge` takes
    hibp_checked: bool = False
    twofa: list[tuple[Login, str]] = field(default_factory=list)   # (login, SUPPORTS or LIKELY)
    twofa_skipped: str = ""    # why the two-step check did not run, or "" when it did
    autofill: list[tuple[Login, str]] = field(default_factory=list)
    masked: list[Login] = field(default_factory=list)                # a masked username that fits no single real one
    fixable: set[str] = field(default_factory=set)                  # item ids `fixurls` would give an https:// address
    old: list[tuple[Login, datetime, str]] = field(default_factory=list)
    recently_added: int = 0
    notes: list[NoteHit] = field(default_factory=list)
    logins: list[Login] = field(default_factory=list)               # live logins with a password

    def flags(self) -> dict[str, set[str]]:
        """Item id -> the reasons it is flagged. Ids and reason names only: this is all the progress file holds."""
        out: dict[str, set[str]] = defaultdict(set)
        for reason, ids in (
                (EXPOSED, [l.item_id for l, _ in self.exposed]), (REUSED, [l.item_id for ls in self.reused.values() for l in ls]),
                (WEAK, [l.item_id for l, _, _ in self.weak]),
                (DUPLICATE, [i["id"] for g in self.dupes for i in [g.keeper, *g.others]]),
                (TWOFA, [l.item_id for l, _ in self.twofa]), (AUTOFILL, [l.item_id for l, _ in self.autofill]),
                (OLD, [l.item_id for l, _, _ in self.old]), (NOTES, [hit.item_id for hit in self.notes]),
                (MASKED, [l.item_id for l in self.masked])):
            for item_id in ids:
                out[item_id].add(reason)
        return dict(out)

    def checks(self) -> set[str]:
        """The checks that ran, so a check that was skipped is never read as everything being fixed."""
        ran = {REUSED, WEAK, DUPLICATE, AUTOFILL, OLD, NOTES, MASKED}
        if self.hibp_checked:
            ran.add(EXPOSED)
        if not self.twofa_skipped:
            ran.add(TWOFA)
        return ran


@dataclass
class Progress:
    """Item ids flagged then and now, on the checks that ran both times. The report turns them into sites."""
    since: str | None = None   # the date of the check-up before this one, None when there was none
    before: set[str] = field(default_factory=set)
    now: set[str] = field(default_factory=set)

    @property
    def new(self) -> set[str]:
        return self.now - self.before


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
    keys = dd.account_keys(items)
    for it in items:
        if it.get("type") != LOGIN_TYPE:
            continue
        login = it.get("login") or {}
        pw = login.get("password") or ""
        if not pw:
            no_password += 1
            continue
        uris = dd.uri_strings(it)
        hosts = [host_from(u) for u in uris]
        first = dd.first_site_uri(uris)
        logins.append(Login(
            item_id=it["id"],
            name=it.get("name") or "(no name)",
            username=login.get("username") or "",
            host=hosts[0] if hosts else "",
            hosts=hosts,
            uris=uris,
            site=dd.site_of(first) if first else "",
            key=keys.get(it["id"]) or f"item:{it['id']}",
            secure=any((p := dd.parse_uri(u)) is not None and p[0] == "https" for u in uris),
            password=pw,
            in_trash=bool(it.get("deletedDate")),
            tier=order.tier(hosts, folders.get(it.get("folderId"))),
            has_totp=bool(login.get("totp")),
            changed=when(login.get("passwordRevisionDate")),
            created=when(it.get("creationDate")),
            revised=it.get("revisionDate") or "",
            has_passkey=bool(dd.passkeys(it)),
            masked_copy=it["id"] in keys and dd.is_masked_copy(it, keys[it["id"]]),
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
    """A login AutoFill will not offer reliably. A device at home (a router) has no https:// page, so it is not flagged."""
    if not l.uris:
        return "no web address saved"
    if not any(dd.is_web_address(u) for u in l.uris) and any(dd.broken_web_address(u) for u in l.uris):
        return "address isn't a web address"
    if dd.http_only(l.uris) and not dd.on_devices(l.uris):
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
    rep.logins = live

    by_hash: dict[str, list[Login]] = defaultdict(list)
    for l in live:
        by_hash[sha1_upper(l.password)].append(l)
    for h, ls in by_hash.items():
        first: dict[str, Login] = {}
        for l in ls:
            first.setdefault(l.key, l)  # copies of one site + username are one account, not reuse
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
        rep.breaches = hibp_counts(set(by_hash))
        for h, n in rep.breaches.items():
            for l in by_hash[h]:
                rep.exposed.append((l, n))
        rep.hibp_checked = True

    rep.dupes = dd.find_groups(items)
    rep.safe_merge = len(dd.select(rep.dupes, "merge")[0])
    rep.fixable = {g.keeper["id"] for g in dd.find_fixes(items)[0]}

    for l in live:
        if twofa and not l.has_totp:
            matches = {twofa.match(h, order.site(h)) for h in l.hosts} - {None}
            if matches:
                rep.twofa.append((l, SUPPORTS if SUPPORTS in matches else LIKELY))
        problem = autofill_problem(l)
        if problem:
            rep.autofill.append((l, problem))
        if dd.MASK in l.username and not l.masked_copy:
            rep.masked.append(l)
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
    return Progress(previous["date"], before, now)


# --- the sites: one per website + username, the unit every count and table uses ---------------------------

@dataclass
class Site:
    key: str
    logins: list[Login]
    problems: dict[str, str] = field(default_factory=dict)   # reason -> a short detail ("" when none)

    @property
    def main(self) -> Login:
        """The copy the account link opens: the one the duplicate cleanup would keep (never a masked copy; a passkey's,
        else the newest)."""
        return max(self.logins, key=lambda l: (not l.masked_copy, l.has_passkey, l.revised, l.item_id))

    @property
    def name(self) -> str:
        """What the Site column shows: the site, or the item's name when it has no address."""
        return self.main.site or self.main.name

    @property
    def tier(self) -> int:
        return min(l.tier for l in self.logins)

    @property
    def ids(self) -> list[str]:
        return sorted(l.item_id for l in self.logins)

    @property
    def rank(self) -> int:
        return min((SEVERITY.index(p) for p in self.problems), default=len(SEVERITY))

    @property
    def urgency(self) -> int:
        """0: a password exposed in a breach. 1: one reused or weak (it needs a new password). 2: the smaller fixes."""
        return 0 if EXPOSED in self.problems else 1 if NEEDS_NEW_PASSWORD & set(self.problems) else 2

    @property
    def linkable(self) -> bool:
        """A change-password link is offered only for a web site saved with an https:// or bare address."""
        site = self.main.site
        return bool(SAFE_HOST.fullmatch(site)) and not dd.is_device(site) and any(l.secure for l in self.logins)


@dataclass
class Model:
    """What both pages are drawn from."""
    rep: Report
    sites: dict[str, Site]
    reuse_labels: dict[str, str]   # sha1 -> "A", "B", ...

    def with_problem(self, reason: str) -> list[Site]:
        return [s for s in self.sites.values() if reason in s.problems]

    @property
    def to_fix(self) -> list[Site]:
        """Most urgent first; within one urgency, by kind of site (email and main accounts first), then the worst problem."""
        return sorted((s for s in self.sites.values() if s.problems), key=lambda s: (s.urgency, s.tier, s.rank, s.name.lower(), s.key))

    @property
    def need_password(self) -> list[Site]:
        return [s for s in self.sites.values() if NEEDS_NEW_PASSWORD & set(s.problems)]


def letters(n: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA: a name for a reused password that says nothing about it."""
    out = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        out = chr(65 + r) + out
    return out


def model_of(rep: Report) -> Model:
    sites: dict[str, Site] = {}
    for l in rep.logins:
        sites.setdefault(l.key, Site(l.key, [])).logins.append(l)
    of = {l.item_id: sites[l.key] for l in rep.logins}

    def mark(item_id: str, reason: str, detail: str = "") -> None:
        if item_id in of:
            of[item_id].problems.setdefault(reason, detail)

    for l, _ in rep.exposed:
        mark(l.item_id, EXPOSED)
    labels = {h: letters(n) for n, (h, _) in enumerate(sorted(rep.reused.items(), key=lambda kv: (-len(kv[1]), kv[1][0].key)))}
    for h, ls in rep.reused.items():
        for l in ls:
            mark(l.item_id, REUSED, f" ×{len(ls)}")
    for l, _, _ in rep.weak:
        mark(l.item_id, WEAK)
    for g in rep.dupes:
        for i in [g.keeper, *g.others]:
            mark(i["id"], DUPLICATE)
    for l, _ in rep.twofa:
        mark(l.item_id, TWOFA)
    for l, _ in rep.autofill:
        mark(l.item_id, AUTOFILL)
    for l, _, _ in rep.old:
        mark(l.item_id, OLD)
    for l in rep.masked:
        mark(l.item_id, MASKED)
    return Model(rep, sites, labels)


# --- HTML: built straight from the data. Every piece of vault text goes through esc(); nothing is Markdown. ----

def esc(text: str) -> str:
    return html.escape(text, quote=True)


def svg(shape: str) -> str:
    """A small inline icon. It always sits next to a word, so screen readers skip it."""
    return (f'<svg class="i" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" focusable="false">'
            f'{SHAPES[shape]}</svg>')


SHAPES = {
    EXPOSED: '<path d="M5 .5 9.7 9.3H.3Z" fill="currentColor"/>',
    REUSED: '<path d="M5 0 10 5 5 10 0 5Z" fill="currentColor"/>',
    WEAK: '<circle cx="5" cy="5" r="4" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M5 1a4 4 0 0 0 0 8Z" fill="currentColor"/>',
    OLD: '<circle cx="5" cy="5" r="4" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M5 2.5V5l2 1.5" fill="none" stroke="currentColor" stroke-width="1.4"/>',
    DUPLICATE: '<rect x=".7" y="3.2" width="5.6" height="5.6" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="3.7" y=".7" width="5.6" height="5.6" fill="currentColor"/>',
    TWOFA: '<circle cx="5" cy="5" r="4" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="5" cy="5" r="1.7" fill="currentColor"/>',
    AUTOFILL: '<path d="M4 0h2v4h4v2H6v4H4V6H0V4h4Z" fill="currentColor"/>',
    MASKED: '<path d="M5 .5v9M1.1 2.75l7.8 4.5M1.1 7.25l7.8-4.5" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    "new": '<path d="m5 0 1.5 3.3 3.5.4-2.6 2.4.7 3.5L5 7.9 1.9 9.6l.7-3.5L0 3.7l3.5-.4Z" fill="currentColor"/>',
    "ok": '<path d="M1 5.2 4 8l5-6.5" fill="none" stroke="currentColor" stroke-width="1.8"/>',
    "tidy": '<rect x="1" y="1" width="8" height="8" fill="currentColor"/>',
    "arrow": '<path d="M2.5 7.5 7.5 2.5M3.5 2.5h4v4" fill="none" stroke="currentColor" stroke-width="1.3"/>',
    "key": '<circle cx="2.4" cy="4" r="1.8" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M4.2 4H9.6M7.4 4v2.6M9 4v2" fill="none" stroke="currentColor" stroke-width="1.2"/>',
}


def chip(kind: str, extra: str = "") -> str:
    return f'<span class="chip c-{kind}">{svg(kind)}{CHIP_WORDS[kind]}{esc(extra)}</span>'


def item_href(vault: str, item_id: str) -> str | None:
    return f"{vault}/#/vault?itemId={item_id}" if vault and SAFE_ID.fullmatch(item_id) else None


def link(href: str, text_html: str, title: str, icon: str) -> str:
    """A value that is also a link: it looks like plain text until hovered. The href is built here, never taken from the vault."""
    return (f'<a class="v" href="{esc(href)}" title="{title}" target="_blank" rel="noopener noreferrer">'
            f'{text_html}{svg(icon)}</a>')


def site_cell(s: Site) -> str:
    """The site's name, linked to its change-password address when it is a web site saved with https://."""
    if s.linkable:
        return link(f"https://{s.main.site}/.well-known/change-password", esc(s.name), "Change password", "arrow")
    return esc(s.name)


def account_html(vault: str, login: Login, text: str | None = None) -> str:
    """The account (or the given text), linked to the item in the Bitwarden web vault."""
    shown = text if text is not None else login.username
    inner = esc(shown) if shown else '<span class="muted">(no username)</span>'
    href = item_href(vault, login.item_id)
    return link(href, inner, "Open in Bitwarden", "key") if href else inner


def copies_cell(vault: str, s: Site) -> str:
    """How many copies, and, opened, one line per copy: its addresses, linked to that copy in Bitwarden, and the
    username as saved only when it differs from the row's (capitals, or a masked copy)."""
    if len(s.logins) == 1 and len(set(s.logins[0].hosts)) <= 1:
        return "1"
    lines = []
    for l in sorted(s.logins, key=lambda l: (l is not s.main, l.hosts, l.item_id)):
        hosts = ", ".join(dict.fromkeys(l.hosts)) or "no address"
        saved = f' <span class="muted">saved as {esc(l.username)}</span>' if l.username != s.main.username else ""
        masked = ' <span class="tag">masked copy</span>' if l.masked_copy else ""
        lines.append(f"<li>{account_html(vault, l, hosts)}{saved}{masked}</li>")
    return f'<details><summary>{len(s.logins)}</summary><ul class="hosts">{"".join(lines)}</ul></details>'


def problem_chips(s: Site, new: bool) -> str:
    out = [chip(p, s.problems[p]) for p in SEVERITY if p in s.problems]
    if new:
        out.append(chip("new"))
    return " ".join(out)


Cell = tuple[str, "str | int | None"]   # (cell html, sort key or None for the cell's text)


def table(cls: str, headers: list[str], rows: list[tuple[list[str], list[Cell]]]) -> str:
    """rows: (the item ids the row stands for, its cells). The ids are what a done tick is kept under."""
    head = "".join(f'<th scope="col">{h}</th>' for h in headers)
    body = []
    for ids, cells in rows:
        safe_ids = " ".join(i for i in ids if SAFE_ID.fullmatch(i))
        attrs = f' data-ids="{esc(safe_ids)}"' if safe_ids else ""
        tds = "".join(f'<td data-sort="{esc(str(k))}">{c}</td>' if k is not None else f"<td>{c}</td>" for c, k in cells)
        body.append(f"<tr{attrs}>{tds}</tr>")
    return (f'<div class="scroll"><table class="list {cls}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def empty_card(anchor: str, title: str, text: str, extra: str = "") -> str:
    """A section with nothing in it: no heading, one line."""
    return f'<section class="card empty" id="{anchor}"><p><strong>{title}:</strong> {text}</p>{extra}</section>'


def section(anchor: str, title: str, intro: str, body: str, extra: str = "") -> str:
    return f'<section class="card" id="{anchor}"><h2>{title}</h2>{intro}{body}{extra}</section>'


def command(paste_line: str, user: str, words: str) -> str:
    """The exact line to run, or, without a known paste line, the words to add to it."""
    if paste_line:
        who = f" --user {user}" if user else ""
        return f"<code>{esc(paste_line)}{esc(who)} {esc(words)}</code>"
    return f"<code>{esc(words)}</code> (added after <code>bash -s --</code> on the paste line)"


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


# --- the dashboard: shared by the report and the summary ------------------------------------------------

CARD_LEVELS = {"urgent": ("Urgent", EXPOSED), "soon": ("Fix soon", REUSED), "check": ("Check", TWOFA), "tidy": ("Tidy", "tidy")}


def card(title: str, value: str, level: str, note: str = "") -> str:
    """A score card. Its level is a word and a shape as well as a color; a zero reads OK."""
    ok = value == "0" and level != "total"
    if not value.isdigit():  # a check that did not run is neither good nor bad
        level, badge = "total", '<span class="lvl lvl-total">Not run</span>'
    elif level == "total":
        badge = '<span class="lvl lvl-total">Total</span>'
    elif ok:
        badge = f'<span class="lvl lvl-ok">{svg("ok")}OK</span>'
    else:
        word, shape = CARD_LEVELS[level]
        badge = f'<span class="lvl lvl-{level}">{svg(shape)}{word}</span>'
    sub = f'<span class="sub">{note}</span>' if note else ""
    return (f'<div class="score s-{"ok" if ok else level}">{badge}<span class="num">{value}</span>'
            f'<span class="what">{title}</span>{sub}</div>')


def ring(work: int, total: int) -> str:
    """Sites needing work against sites with nothing to do. The two parts differ in thickness as well as color."""
    c = 2 * math.pi * 50
    part = c * work / total if total else 0
    return (f'<figure class="ring"><svg viewBox="0 0 120 120" width="150" height="150" role="img" '
            f'aria-label="{work} of {total} sites need work">'
            f'<circle cx="60" cy="60" r="50" fill="none" class="ring-fine" stroke-width="8"/>'
            f'<circle cx="60" cy="60" r="50" fill="none" class="ring-work" stroke-width="16" '
            f'stroke-dasharray="{part:.2f} {c:.2f}" transform="rotate(-90 60 60)"/>'
            f'<text x="60" y="62" text-anchor="middle" class="ring-num">{work}</text>'
            f'<text x="60" y="80" text-anchor="middle" class="ring-of">of {total} need work</text></svg>'
            f'<figcaption><span class="legend"><svg class="sw" width="22" height="10" aria-hidden="true"><rect y="1" width="22" height="8" '
            f'class="sw-work"/></svg>{work} need work</span><span class="legend"><svg class="sw" width="22" height="10" aria-hidden="true">'
            f'<rect y="4" width="22" height="2" class="sw-fine"/></svg>{total - work} with nothing to do</span></figcaption></figure>')


def bars(title: str, rows: list[tuple[str, str, int | None]], hide_zero: bool = False) -> str:
    """Horizontal bars, each with its word and its number: the color only repeats what the word says.
    rows: (word, kind, count), the kind naming the color and, for a problem, its shape; None: not checked this run.
    hide_zero leaves out a row whose count is 0 (a check that did not run is still shown)."""
    rows = [r for r in rows if not (hide_zero and r[2] == 0)]
    top = max((n for _, _, n in rows if n is not None), default=0) or 1
    out = "".join(f'<div class="bar"><span class="bl">{svg(kind) if kind in SHAPES else ""}{esc(word)}</span>'
                  f'<span class="track"><span class="fill f-{kind}" style="width:{100 * (n or 0) / top:.1f}%"></span></span>'
                  f'<span class="bn">{"not checked" if n is None else n}</span></div>' for word, kind, n in rows)
    return f'<div class="bars"><h3>{title}</h3>{out}</div>'


def dashboard(m: Model, for_summary: bool, after_headline: str = "") -> str:
    rep = m.rep
    total, need, work = len(m.sites), len(m.need_password), len(m.to_fix)
    smaller, fine = work - need, total - work
    exposed = str(len(m.with_problem(EXPOSED))) if rep.hibp_checked else "not checked"
    twofa = "not checked" if rep.twofa_skipped else str(len(m.with_problem(TWOFA)))
    cards = "".join([
        card("Sites", str(total), "total", "one per website and username"),
        card("Need a new password", str(need), "urgent"),
        card("Exposed", exposed, "urgent"),
        card("Reused", str(len(m.with_problem(REUSED))), "soon"),
        card("Weak", str(len(m.with_problem(WEAK))), "soon"),
        card("Duplicates", str(len(m.with_problem(DUPLICATE))), "tidy", "" if for_summary else f"{rep.safe_merge} groups safe to merge"),
        card("Two-step to check", twofa, "check"),
        card("AutoFill fixes", str(len(m.with_problem(AUTOFILL))), "tidy", "" if for_summary else f"{len(rep.fixable)} can be fixed for you"),
    ])
    headline = (f'<p class="headline"><strong>{need} of your {total} sites need a new password</strong>: the password is exposed '
                f'in a breach, reused on another site, or weak. {plural(smaller, "more site needs", "more sites need")} a smaller '
                f'fix: two-step login to check, an AutoFill address, a duplicate to merge, a masked username or an old password. The other {fine} '
                f'{"has" if fine == 1 else "have"} nothing to do. A site is one website and one username: copies of the same login, '
                f'and its other addresses, count once.</p>')
    notes = f'<p class="muted">Separately, {plural(len(rep.notes), "note", "notes")} may hold a password.</p>' if rep.notes else ""
    not_run = {EXPOSED} if not rep.hibp_checked else set()
    not_run |= {TWOFA} if rep.twofa_skipped else set()
    problem_rows = [(CHIP_WORDS[p], p, None if p in not_run else len(m.with_problem(p))) for p in SEVERITY]
    tier_rows = [(f"{t} · {name}", "tier", sum(1 for s in m.to_fix if s.tier == t)) for t, name in TIER_NAMES.items()]
    return (f'<section class="dash">{ring(work, total)}<div class="lead">{headline}{notes}</div></section>{after_headline}'
            f'<div class="scores">{cards}</div><div class="charts">{bars("Sites per problem", problem_rows, for_summary)}'
            f'{bars("Sites to fix, by kind of site", tier_rows, for_summary)}</div>')


# --- the report ------------------------------------------------------------------------------------------

def breach_bar(n: int) -> str:
    """The count, with a bar on a log scale: ten million times or more fills it."""
    width = min(100.0, 100 * math.log10(n + 1) / 7)
    return f'<span class="meter"><span class="mfill f-exposed" style="width:{width:.0f}%"></span></span> {n:,}'


def strength_bar(score: int) -> str:
    """Four segments, as many filled as the score, and the score in words."""
    segs = "".join(f'<span class="seg{" on" if k < score else ""}"></span>' for k in range(4))
    return f'<span class="strength" aria-hidden="true">{segs}</span> {score} of 4'


def render(rep: Report, progress: Progress, vault_url: str, stamp: str, paste_line: str, user: str) -> str:
    vault = vault_url if SAFE_VAULT_URL.fullmatch(vault_url) else ""
    m = model_of(rep)

    def is_new(s: Site) -> bool:
        """Flagged now, and none of its copies flagged last time."""
        return bool(set(s.ids) & progress.now) and not set(s.ids) & progress.before

    def who(s: Site) -> str:
        return account_html(vault, s.main)

    def where(s: Site) -> list[Cell]:
        return [(site_cell(s), s.name.lower()), (who(s), s.main.username.lower())]

    flagged = rep.flags()
    left = len(m.to_fix)
    if progress.since is None:
        progress_line = (f"<strong>First check-up of this vault on this Mac: {plural(left, 'site needs', 'sites need')} work.</strong> "
                         "The next one will show what changed.")
        entries = f"In Bitwarden entries: {len(flagged)} flagged."
    else:
        fixed = sum(1 for s in m.sites.values() if set(s.ids) & progress.before and not set(s.ids) & progress.now)
        new_sites = sum(1 for s in m.to_fix if is_new(s))
        progress_line = (f"<strong>{fixed} fixed since {esc(progress.since)}, {plural(left, 'site', 'sites')} left, {new_sites} new.</strong>"
                         + (" New ones are marked NEW." if new_sites else ""))
        entries = (f"In Bitwarden entries: {len(flagged)} flagged, {len(progress.before - progress.now)} fixed and "
                   f"{len(progress.new)} new since {esc(progress.since)}.")
    totals = (f'<p class="totals muted">Logins with a password: {rep.total - rep.trashed} · In trash (ignored, empty it): '
              f'{rep.trashed} · Logins with no password: {rep.no_password} · Distinct passwords reused: {len(rep.reused)} · {entries}</p>')

    parts = [f'<header><h1>Bitwarden check-up</h1><p class="date">Check-up of {esc(stamp)}.</p>'
             f'<p class="progress">{progress_line}</p></header>', dashboard(m, for_summary=False), totals]
    first = m.to_fix[:FIX_FIRST]
    if first:
        items = "".join(f"<li>{site_cell(s)} · {who(s)} {problem_chips(s, is_new(s))}</li>" for s in first)
        parts.append(f'<section class="card" id="first"><h2>Fix these first</h2><p class="muted">The top {len(first)}: an exposed '
                     f'password first, then a reused or weak one, then the smaller fixes; within each, by kind of site.</p>'
                     f'<ol class="first">{items}</ol></section>')
    parts += ['<p class="help">Click a site to change its password (if you land on the home page, look under account settings). '
              'Click the account to open it in Bitwarden.</p>', TOOLS]

    # Everything to fix: one row per site.
    if m.to_fix:
        rows = [(s.ids, [(f"{s.tier} · {esc(TIER_NAMES[s.tier])}", s.tier), *where(s),
                         (problem_chips(s, is_new(s)), s.urgency * 100 + s.rank), (copies_cell(vault, s), len(s.logins))]) for s in m.to_fix]
        masked_note = ('<p class="muted">Masked: the username was saved with * in place of some letters (an export can do that), '
                       'so this entry will not sign in until the real username is typed in Bitwarden.</p>') if rep.masked else ""
        parts.append(section("fix", "Fix in this order", "<p>Most serious first: a password exposed in a breach, then one reused or "
                             "weak, then the smaller fixes. Within each, email and main accounts first, then money and shopping, then "
                             "phone, utilities, insurance and health, then gaming and social, then everything else.</p>",
                             table("main", ["Kind of site", "Site", "Account", "Problems", "Copies"], rows), masked_note))
    else:
        parts.append(empty_card("fix", "Fix in this order", "Nothing found. Every live password is unique, strong and unseen in a breach."))

    # Exposed.
    if not rep.hibp_checked:
        parts.append(empty_card("exposed", "Exposed in a breach", "not checked this run (--no-hibp)."))
    elif m.with_problem(EXPOSED):
        seen: dict[str, int] = defaultdict(int)
        for l, n in rep.exposed:
            seen[l.key] = max(seen[l.key], n)
        rows = [(s.ids, [*where(s), (breach_bar(seen[s.key]), seen[s.key])])
                for s in sorted(m.with_problem(EXPOSED), key=lambda s: (-seen[s.key], s.name.lower()))]
        parts.append(section("exposed", "Exposed in a breach", "<p>Change these today. The count is how many times that exact "
                             "password appears in public breach lists.</p>", table("exposed", ["Site", "Account", "Seen in breaches"], rows)))
    else:
        parts.append(empty_card("exposed", "Exposed in a breach", "Nothing found."))

    # Reused: one row per password, never the password itself.
    if rep.reused:
        rows = []
        for h, ls in sorted(rep.reused.items(), key=lambda kv: (len(m.reuse_labels[kv[0]]), m.reuse_labels[kv[0]])):
            members = sorted({l.key: m.sites[l.key] for l in ls}.values(), key=lambda s: s.name.lower())
            listed = "".join(f"<li>{site_cell(s)} · {who(s)}</li>" for s in members)
            if h in rep.breaches:
                breached = f"{chip(EXPOSED)} seen {rep.breaches[h]:,} times"
            else:
                breached = "No" if rep.hibp_checked else "not checked"
            rows.append(([i for s in members for i in s.ids],
                         [(f"Password {m.reuse_labels[h]}", f"{len(m.reuse_labels[h]):02d}{m.reuse_labels[h]}"), (str(len(ls)), len(ls)),
                          (f'<details><summary>{plural(len(members), "site", "sites")}</summary><ul class="hosts">{listed}</ul></details>', None),
                          (breached, rep.breaches.get(h, 0))]))
        parts.append(section("reused", "Reused passwords", "<p>Each group is one password used on several sites. The password itself "
                             "is never shown: give each site its own.</p>",
                             table("reused", ["Group", "Used on N sites", "Sites", "Any exposed?"], rows)))
    else:
        parts.append(empty_card("reused", "Reused passwords", "Nothing found."))

    # Weak: a site's weakest password.
    if rep.weak:
        worst: dict[str, tuple[int, str]] = {}
        for l, score, warning in rep.weak:
            if l.key not in worst or score < worst[l.key][0]:
                worst[l.key] = (score, warning)
        rows = [(s.ids, [*where(s), (strength_bar(worst[s.key][0]), worst[s.key][0]), (esc(worst[s.key][1] or "short or predictable"), None)])
                for s in sorted(m.with_problem(WEAK), key=lambda s: (worst[s.key][0], s.name.lower()))]
        parts.append(section("weak", "Weak passwords", "<p>Strength runs from 0 (guessed at once) to 4 (strong).</p>",
                             table("weak", ["Site", "Account", "Strength (0-4)", "Why"], rows)))
    else:
        parts.append(empty_card("weak", "Weak passwords", "Nothing found."))

    # Duplicates: the duplicate cleanup's own groups, so the report says exactly what it would do.
    if rep.dupes:
        rows = []
        for g in sorted(rep.dupes, key=lambda g: g.account):
            members = [g.keeper, *g.others]
            site = g.account.partition("|")[0]
            keeper_user = dd.login_of(g.keeper).get("username") or ""
            href = item_href(vault, g.keeper["id"])
            account = link(href, esc(keeper_user), "Open in Bitwarden", "key") if href else esc(keeper_user)
            s = m.sites.get(g.account)
            if not g.blocked:
                safe, order_key = "Yes", 0
            elif g.blocked in dd.PICK_REASONS:
                safe, order_key = "Needs pick", 1
            else:
                safe, order_key = f"No: {esc(g.blocked)}", 2
            rows.append(([i["id"] for i in members], [(site_cell(s) if s else esc(site), site), (account, keeper_user.lower()),
                                                       (str(len(members)), len(members)), (safe, order_key)]))
        how = (f"<p>{plural(rep.safe_merge, 'group is', 'groups are')} safe to merge: same site, same username and the same password. "
               f"Merging keeps one copy (the one with a passkey, otherwise the newest), adds the others' addresses, notes, one-time "
               f"code and custom fields to it, and moves the rest to Bitwarden's Trash for 30 days. See what it would do, changing "
               f"nothing: {command(paste_line, user, 'dedupe merge')}. Then act on one group first: "
               f"{command(paste_line, user, 'dedupe merge apply 1')}, and type DEDUPE when asked. \"Needs pick\" means the copies "
               f"have different passwords, or one copy's username is masked with *: {command(paste_line, user, 'dedupe pick')} "
               f"shows each copy's addresses and dates, and lets you choose the password that works or keep both.</p>")
        parts.append(section("duplicates", "Duplicate entries", "<p>The same site and username saved more than once, usually one "
                             "copy from Apple and one from Chrome.</p>",
                             table("dupes", ["Site", "Account", "Copies", "Safe to merge?"], rows), how))
    else:
        parts.append(empty_card("duplicates", "Duplicate entries", "Nothing found."))

    # Two-step: one row per website, its accounts listed.
    credit = ('<p class="credit muted">Data sourced from <a href="https://2fa.directory/" target="_blank" '
              'rel="noopener noreferrer">2FA Directory</a> by 2factorauth.</p>')
    if rep.twofa_skipped:
        parts.append(section("two-step", "Two-step login", f"<p>Not checked this run: {esc(rep.twofa_skipped)}. "
                             "This does not mean none were found.</p>", ""))
    elif rep.twofa:
        how_of = {l.item_id: how for l, how in rep.twofa}
        by_site: dict[str, list[Site]] = defaultdict(list)
        for s in m.with_problem(TWOFA):
            by_site[s.name].append(s)
        rows = []
        for name, group in sorted(by_site.items(), key=lambda kv: (min(s.tier for s in kv[1]), kv[0].lower())):
            matches = {how_of[i] for s in group for i in s.ids if i in how_of}
            accounts = ", ".join(who(s) for s in sorted(group, key=lambda s: s.main.username.lower()))
            rows.append(([i for s in group for i in s.ids],
                         [(site_cell(group[0]), name.lower()), (accounts, None), (SUPPORTS if SUPPORTS in matches else LIKELY, None)]))
        intro = ("<p>For each site below: this site offers two-step login; check it's on. No one-time code is saved in the "
                 "Bitwarden entry, and the entry cannot show whether two-step login is already on at the site (a text message or "
                 "another app would not show here).</p>"
                 f"<p>\"{SUPPORTS.capitalize()}\" means the saved address itself is on the public list. \"{LIKELY.capitalize()}\" "
                 "means only a related address is: one above or below it, or another address of the same site.</p>")
        parts.append(section("two-step", "Two-step login", intro, table("twofa", ["Site", "Accounts", "Match"], rows), credit))
    else:
        parts.append(empty_card("two-step", "Two-step login", "Nothing found.", credit))

    # AutoFill.
    if rep.autofill:
        problem_of = {l.item_id: p for l, p in rep.autofill}
        rows = [(s.ids, [*where(s), (esc(", ".join(sorted({problem_of[i] for i in s.ids if i in problem_of}))), None)])
                for s in sorted(m.with_problem(AUTOFILL), key=lambda s: s.name.lower())]
        fixable = len(rep.fixable)
        how = (f"<p>{plural(fixable, 'login', 'logins')} saved with only an http:// address can get the https:// address added for "
               f"you, and nothing else changes. See the list first, changing nothing: {command(paste_line, user, 'fixurls')}. Then "
               f"act on one: {command(paste_line, user, 'fixurls apply 1')}, and type FIXURLS when asked. A login that holds a "
               f"passkey is left for you to fix by hand.</p>") if fixable else ""
        parts.append(section("autofill", "AutoFill problems", "<p>iPhone AutoFill matches a login by its web address, so these will "
                             "not be offered reliably. Add the site's https:// address to the entry.</p>",
                             table("autofill", ["Site", "Account", "Problem"], rows), how))
    else:
        parts.append(empty_card("autofill", "AutoFill problems", "Nothing found."))

    # Old passwords: they mean something only once the import's dates are behind.
    if rep.old:
        oldest: dict[str, tuple[datetime, str]] = {}
        for l, since, kind in rep.old:
            if l.key not in oldest or since < oldest[l.key][0]:
                oldest[l.key] = (since, kind)
        rows = [(s.ids, [(f"{s.tier} · {esc(TIER_NAMES[s.tier])}", s.tier), *where(s),
                         (f"{oldest[s.key][1]} {oldest[s.key][0].astimezone():%Y-%m-%d}", oldest[s.key][0].isoformat())])
                for s in sorted(m.with_problem(OLD), key=lambda s: (s.tier, oldest[s.key][0]))]
        later = (f'<p class="muted">{plural(rep.recently_added, "login was", "logins were")} added in the last 30 days (an import, '
                 "for example) and will be checked on later runs.</p>") if rep.recently_added else ""
        parts.append(section("old", "Passwords unchanged for 3+ years", "", table("old", ["Priority", "Site", "Account", "Since"], rows), later))
    elif rep.recently_added and rep.recently_added == len(rep.logins):
        parts.append(empty_card("old", "Passwords unchanged for 3+ years", "Checked on later runs."))
    else:
        later = (f" {plural(rep.recently_added, 'login', 'logins')} added in the last 30 days will be checked on later runs."
                 if rep.recently_added else "")
        parts.append(empty_card("old", "Passwords unchanged for 3+ years", f"Nothing found.{later}"))

    # Notes: the item's name and the reason, never the note.
    if rep.notes:
        rows = []
        for hit in sorted(rep.notes, key=lambda x: x.name.lower()):
            href = item_href(vault, hit.item_id)
            name = link(href, esc(hit.name), "Open in Bitwarden", "key") if href else esc(hit.name)
            if hit.item_id in progress.new:
                name += " " + chip("new")
            rows.append(([hit.item_id], [(name, hit.name.lower()), (hit.kind, None), (esc(hit.reason), None)]))
        parts.append(section("notes", "Notes that may hold a password", "<p>A password kept in a note is not checked, not filled in "
                             "and easy to forget. Move it into the entry's password field, or a hidden custom field. The note's text "
                             "is never shown here.</p>", table("notes", ["Item", "Kind", "Why"], rows)))
    else:
        parts.append(empty_card("notes", "Notes that may hold a password", "Nothing found."))

    # Your Bitwarden account.
    if vault:
        pointers = (f'<ul><li><a href="{esc(vault)}/#/settings/account" target="_blank" rel="noopener noreferrer">Account settings</a>: '
                    "a notice at the top asks you to verify your email if it is not verified yet.</li>"
                    f'<li><a href="{esc(vault)}/#/settings/security/two-factor" target="_blank" rel="noopener noreferrer">Two-step '
                    "login</a>: Settings, then Security, then Two-step login.</li></ul>")
    else:
        pointers = ("<ul><li>In the Bitwarden web vault, open Settings, then My account: a notice asks you to verify your email if it "
                    "is not verified yet.</li><li>In the Bitwarden web vault, open Settings, then Security, then Two-step login.</li></ul>")
    parts.append(section("account", "Your Bitwarden account", "<p>This check-up cannot see whether your Bitwarden email address is "
                         "verified, or whether two-step login is turned on for Bitwarden itself. Please check both:</p>", pointers))
    parts.append('<footer class="muted">Passwords themselves are never shown in this report. Breach check: Have I Been Pwned '
                 'range API (k-anonymity).</footer>')
    return page("Bitwarden check-up", "".join(parts), SCRIPT)


# --- the summary: counts only, to share ------------------------------------------------------------------

HOW_USED = {
    EXPOSED: "Leaked passwords are loaded into tools that try them on thousands of sites within minutes, and AI makes that "
             "cheaper still.",
    REUSED: "One leak from any site unlocks every other site that shares the password: tools try it everywhere automatically.",
    WEAK: "Guessing tools, now helped by AI trained on leaked passwords, try names, words and patterns first: a weak password "
          "falls in seconds.",
    OLD: "A password unchanged for years has had years to leak in a breach nobody heard about.",
    DUPLICATE: "Old copies keep an old password alive after it is changed, and AutoFill may offer the stale one.",
    TWOFA: "Without a second step, a stolen or guessed password is all an attacker needs, and phishing kits now automate "
           "the login.",
    AUTOFILL: "When AutoFill does not offer a login, it is easier to type the password into a fake page that looks like the real one.",
}


def plan_steps(m: Model) -> str:
    """Three steps in the order the report fixes things, each with how many sites it covers: generic words, no site."""
    steps = [
        ("Email and main accounts first", "email; Apple, Google and Microsoft accounts; government and ID sites", {1},
         "Give each its own new password from Bitwarden's generator, and turn on two-step login wherever the site offers it."),
        ("Then money", "banks, cards, payment and shopping sites", {2},
         "The same way: a new password each, and two-step login where it is offered."),
        ("Then the rest", "", set(TIER_NAMES) - {1, 2},
         "Most serious first: an exposed password, then a reused or weak one; then the tidy-ups (duplicate entries, AutoFill addresses)."),
    ]
    out = []
    for name, covers, tiers, how in steps:
        n = sum(1 for s in m.to_fix if s.tier in tiers)
        what = f"{plural(n, 'site needs', 'sites need')} work. {how}" if n else "nothing needs work here."
        out.append(f"<li><strong>{name}</strong>{f' ({covers})' if covers else ''}: {what}</li>")
    return '<section class="card"><h2>What we\'ll do</h2><ol class="steps">' + "".join(out) + "</ol></section>"


def render_summary(rep: Report, stamp: str, user: str) -> str:
    """Counts by kind of site only: no site, username, host, item id or link."""
    m = model_of(rep)
    risks = []
    for tier, name in TIER_NAMES.items():
        here = [s for s in m.to_fix if s.tier == tier]
        if here:
            what = ", ".join(f"{n} {CHIP_WORDS[p].lower()}" for p in SEVERITY if (n := sum(1 for s in here if p in s.problems)))
            risks.append(f"<li><strong>{esc(name)}:</strong> {plural(len(here), 'site needs', 'sites need')} work ({what}).</li>")
    how = "".join(f"<li>{chip(p)} {HOW_USED[p]}</li>" for p in SEVERITY if p in HOW_USED and m.with_problem(p))
    whose = f" for {esc(user)}" if user else ""
    body = (f'<header><h1>Bitwarden summary{whose}</h1><p class="date">Check-up of {esc(stamp)}. Counts only: no site, username '
            f'or password is on this page.</p></header>{dashboard(m, for_summary=True, after_headline=plan_steps(m))}'
            f'<section class="card"><h2>Top risks, by kind of site</h2>'
            f'{"<ul>" + "".join(risks) + "</ul>" if risks else "<p>Nothing found.</p>"}</section>'
            f'<section class="card"><h2>How an attacker or AI tool would use this</h2>'
            f'{"<ul class=how>" + how + "</ul>" if how else "<p>Nothing found.</p>"}</section>'
            '<footer class="muted">Made by the bw-health check-up. The passwords were checked on this computer and never shown.</footer>')
    return page(f"Bitwarden summary{whose}", body, "")


# --- the page ---------------------------------------------------------------------------------------------

TOOLS = ('<div id="tools" class="tools" hidden><label>Filter <input id="filter" type="search" placeholder="site or account"></label>'
         '<label><input id="hide-done" type="checkbox"> Hide done</label>'
         '<span id="no-store" class="muted" hidden>This browser will not remember the done ticks once the page is closed.</span></div>')

STYLE = """
:root{--bg:#fbfbfa;--card:#fff;--ink:#1b1b1b;--muted:#5d5d5d;--line:#d9d9d6;--track:#e6e6e3;
--red:#b3261e;--red-bg:#fde7e5;--orange:#a84f00;--orange-bg:#ffe9d6;--amber:#7d5b00;--amber-bg:#fff4cc;
--gray:#4f5359;--gray-bg:#eceef0;--blue:#1d5fb4;--blue-bg:#e3eefc;--purple:#6b3fa0;--purple-bg:#efe6fa;
--brown:#6d4c33;--brown-bg:#f1e8e0;--teal:#0f6466;--teal-bg:#dcf1f1;--green:#2e6b30;--tier:#5d6168}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--card:#1f1f1f;--ink:#ececec;--muted:#a9a9a9;--line:#3a3a3a;--track:#333;
--red:#ff9a91;--red-bg:#4a1d1a;--orange:#ffb36b;--orange-bg:#47290c;--amber:#f2cf5b;--amber-bg:#3f3407;
--gray:#c4c8cd;--gray-bg:#2f3236;--blue:#8fbaf5;--blue-bg:#16304f;--purple:#cfa8f7;--purple-bg:#352349;
--brown:#dbb89a;--brown-bg:#3a2a1e;--teal:#7fd3d3;--teal-bg:#123738;--green:#8fd18f;--tier:#b4b8bd}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.7rem;margin:0}h2{font-size:1.2rem;margin:0 0 .5rem}h3{font-size:1rem;margin:0 0 .5rem}
p{margin:.4rem 0}.muted{color:var(--muted)}.date{color:var(--muted);margin:.1rem 0 .4rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
.card.empty{padding:10px 16px}
.dash{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:16px 0}
.lead{flex:1 1 300px}.headline{font-size:1.05rem}
.ring{margin:0 auto;text-align:center}.ring figcaption{font-size:.8rem;color:var(--muted);display:flex;flex-direction:column}
.ring-fine{stroke:var(--muted);stroke-opacity:.45}.ring-work{stroke:var(--orange)}
.ring-num{font-size:30px;font-weight:700;fill:var(--ink)}.ring-of{font-size:9px;fill:var(--muted)}
.legend{display:inline-flex;align-items:center;gap:6px;justify-content:center}.sw-work{fill:var(--orange)}.sw-fine{fill:var(--muted);fill-opacity:.45}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.score{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--gray);border-radius:8px;padding:10px 12px;display:flex;flex-direction:column}
.score .num{font-size:1.7rem;font-weight:700;line-height:1.2}.score .what{font-weight:600}.score .sub{font-size:.8rem;color:var(--muted)}
.s-urgent{border-left-color:var(--red)}.s-soon{border-left-color:var(--orange)}.s-check{border-left-color:var(--blue)}
.s-tidy{border-left-color:var(--purple)}.s-ok{border-left-color:var(--green)}.s-total{border-left-color:var(--tier)}
.lvl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;display:inline-flex;gap:4px;align-items:center}
.lvl-urgent{color:var(--red)}.lvl-soon{color:var(--orange)}.lvl-check{color:var(--blue)}.lvl-tidy{color:var(--purple)}
.lvl-ok{color:var(--green)}.lvl-total{color:var(--muted)}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin:16px 0}
.bars{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.bar{display:grid;grid-template-columns:minmax(110px,45%) 1fr 2.5em;gap:8px;align-items:center;margin:4px 0;font-size:.9rem}
.bl{display:inline-flex;gap:5px;align-items:center}.bn{text-align:right;font-variant-numeric:tabular-nums}
.track{background:var(--track);border-radius:4px;height:12px;display:block;overflow:hidden}
.meter{background:var(--track);border-radius:4px;display:inline-block;width:90px;height:10px;vertical-align:middle;overflow:hidden}
.fill,.mfill{display:block;height:100%}
.f-exposed{background:var(--red)}.f-reused{background:var(--orange)}.f-weak{background:var(--amber)}.f-old{background:var(--brown)}
.f-duplicate{background:var(--gray)}.f-two-step{background:var(--blue)}.f-autofill{background:var(--purple)}.f-masked{background:var(--teal)}.f-tier{background:var(--tier)}
.bl .i{color:var(--ink)}
.chip{display:inline-flex;align-items:center;gap:4px;font-size:.78rem;font-weight:600;padding:1px 7px;border-radius:999px;border:1px solid;white-space:nowrap;margin:1px 0}
.c-exposed{color:var(--red);background:var(--red-bg)}.c-reused{color:var(--orange);background:var(--orange-bg)}
.c-weak{color:var(--amber);background:var(--amber-bg)}.c-old{color:var(--brown);background:var(--brown-bg)}
.c-duplicate{color:var(--gray);background:var(--gray-bg)}.c-two-step{color:var(--blue);background:var(--blue-bg)}
.c-autofill{color:var(--purple);background:var(--purple-bg)}.c-masked{color:var(--teal);background:var(--teal-bg)}
.tag{font-size:.75rem;border:1px solid var(--line);border-radius:4px;padding:0 4px;margin-left:4px}.c-new{color:var(--ink);background:var(--card);border-style:dashed}
.i{flex:none;vertical-align:-1px}a.v .i{margin-left:3px;color:var(--muted)}
a{color:var(--blue)}a.v{color:inherit;text-decoration:none}a.v:hover,a.v:focus{text-decoration:underline}
.help{font-weight:600;margin:16px 0 0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
th button.sort{all:unset;cursor:pointer}th[aria-sort=ascending] button::after{content:" ▲"}th[aria-sort=descending] button::after{content:" ▼"}
tr.done td{text-decoration:line-through;opacity:.6}tr.done td.done-col{text-decoration:none;opacity:1}
details summary{cursor:pointer}ul.hosts{margin:.3rem 0;padding-left:1.1rem;font-size:.85rem}
ol.first{margin:.3rem 0;padding-left:1.4rem}ol.first li{margin:.25rem 0}
.strength{display:inline-flex;gap:2px;vertical-align:middle}.seg{width:14px;height:10px;border:1px solid var(--amber);border-radius:2px}
.seg.on{background:var(--amber)}
.tools{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin:12px 0}[hidden]{display:none!important}.tools input[type=search]{font:inherit;padding:4px 8px}
code{font-size:.85rem;background:var(--track);padding:1px 4px;border-radius:4px;word-break:break-all}
ul.how{padding-left:0;list-style:none}ul.how li{margin:.5rem 0}ol.steps{padding-left:1.4rem;margin:.2rem 0}ol.steps li{margin:.4rem 0}
footer{margin-top:24px;font-size:.85rem}
@media print{body{background:#fff;color:#000;-webkit-print-color-adjust:exact;print-color-adjust:exact}.tools,.done-col{display:none!important}.card,.score,.bars{break-inside:avoid}
a.v .i{display:none}main{padding:0}}
"""

SCRIPT = """
(function(){
  var KEY='bw-health-done', done={};
  function unkept(){ document.getElementById('no-store').hidden=false; }  // storage blocked: say so, keep ticks for this view
  try{ done=JSON.parse(localStorage.getItem(KEY)||'{}')||{}; }catch(e){ unkept(); }
  function save(){ try{ localStorage.setItem(KEY, JSON.stringify(done)); }catch(e){ unkept(); } }
  var tools=document.getElementById('tools'), filter=document.getElementById('filter'), hide=document.getElementById('hide-done');
  tools.hidden=false;
  var rows=[].slice.call(document.querySelectorAll('tr[data-ids]'));
  function ids(tr){ return tr.getAttribute('data-ids').split(' ').filter(Boolean); }
  function isDone(tr){ return ids(tr).some(function(i){ return done[i]; }); }
  function refresh(){
    var q=filter.value.trim().toLowerCase();
    rows.forEach(function(tr){
      var d=isDone(tr), cb=tr.querySelector('input.done-box');
      tr.classList.toggle('done', d); if(cb) cb.checked=d;
      tr.hidden=(hide.checked && d) || (q!=='' && tr.textContent.toLowerCase().indexOf(q)<0);
    });
  }
  function key(td){ var v=td.getAttribute('data-sort'); if(v===null) v=td.textContent.trim().toLowerCase();
    return (v!=='' && !isNaN(v)) ? Number(v) : v; }
  [].forEach.call(document.querySelectorAll('table.list'), function(t){
    var hr=t.tHead.rows[0], th=document.createElement('th');
    th.textContent='Done'; th.className='done-col'; hr.insertBefore(th, hr.firstChild);
    [].forEach.call(t.tBodies[0].rows, function(tr){
      var td=document.createElement('td'); td.className='done-col';
      if(tr.hasAttribute('data-ids')){
        var cb=document.createElement('input'); cb.type='checkbox'; cb.className='done-box'; cb.setAttribute('aria-label','Mark done');
        cb.addEventListener('change', function(){ ids(tr).forEach(function(i){ if(cb.checked) done[i]=1; else delete done[i]; }); save(); refresh(); });
        td.appendChild(cb);
      }
      tr.insertBefore(td, tr.firstChild);
    });
    [].forEach.call(hr.cells, function(cell, idx){
      if(cell.className==='done-col') return;
      var b=document.createElement('button'); b.type='button'; b.className='sort'; b.textContent=cell.textContent;
      cell.textContent=''; cell.appendChild(b);
      b.addEventListener('click', function(){
        var asc=cell.getAttribute('aria-sort')!=='ascending', body=t.tBodies[0], list=[].slice.call(body.rows);
        [].forEach.call(hr.cells, function(c){ c.removeAttribute('aria-sort'); });
        cell.setAttribute('aria-sort', asc?'ascending':'descending');
        list.sort(function(a,b){ var x=key(a.cells[idx]), y=key(b.cells[idx]);
          if(typeof x!==typeof y){ x=String(x); y=String(y); } return (x<y?-1:x>y?1:0)*(asc?1:-1); });
        list.forEach(function(r){ body.appendChild(r); });
      });
    });
  });
  filter.addEventListener('input', refresh); hide.addEventListener('change', refresh);
  window.addEventListener('beforeprint', function(){ [].forEach.call(document.querySelectorAll('details'), function(d){ d.open=true; }); });
  refresh();
})();
"""


def page(title: str, body: str, script: str) -> str:
    """One self-contained page: no external script, style, font or image."""
    js = f"<script>{script}</script>" if script else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="referrer" content="no-referrer"><title>{esc(title)}</title><style>{STYLE}</style></head>'
            f'<body><main>{body}</main>{js}</body></html>')


def write_page(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    os.chmod(path, 0o600)
    print(f"wrote {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--input", help="JSON array from `bw list items` (file path or - for stdin) instead of calling bw")
    ap.add_argument("--folders", help="with --input: JSON array from `bw list folders`, for the folder lines of the fix order")
    ap.add_argument("--vault-url", default=DEFAULT_VAULT_URL, help="with --input: the web vault the links open (bw's server otherwise)")
    ap.add_argument("--out", help="write the HTML report here instead of stdout")
    ap.add_argument("--summary", help="also write the shareable summary (counts only) here")
    ap.add_argument("--summary-only", action="store_true", help="write only the summary: no report, and the progress file is not touched")
    ap.add_argument("--paste-line", default="", help="the pinned paste line, so the report can show the exact commands to run")
    ap.add_argument("--user", default="", help="the --user profile name, for the commands shown and the summary's title")
    ap.add_argument("--no-hibp", action="store_true", help="skip the Have I Been Pwned breach check")
    ap.add_argument("--no-twofa", action="store_true", help="skip the two-step login check")
    ap.add_argument("--twofa-file", help="a saved copy of the 2FA Directory list (v4 all.json) instead of downloading it")
    ap.add_argument("--twofa-cache", help="keep the downloaded 2FA Directory list here and reuse it for a day")
    ap.add_argument("--fix-order", default=str(Path(__file__).with_name("fix_order.txt")),
                    help="the fix-order list (default: fix_order.txt beside this script)")
    ap.add_argument("--state", help="progress file: compared with the last check-up, then rewritten (item ids and reasons only)")
    args = ap.parse_args()
    if args.summary_only and (not args.summary or args.out or args.state):
        sys.exit("--summary-only needs --summary, and takes no --out or --state: it writes the summary and nothing else")
    if args.paste_line and not SAFE_PASTE_LINE.fullmatch(args.paste_line):
        sys.exit("--paste-line is not a bw-health paste line pinned to a version")
    if args.user and not SAFE_USER.fullmatch(args.user):
        sys.exit("--user is 1 to 32 lowercase letters, digits or hyphens")

    order = load_fix_order(Path(args.fix_order))
    dd.suffix_list()  # read before the vault, so a missing or cut-off list stops the run first
    items, folders, vault_url = load_vault(args)
    if args.no_twofa:
        twofa, skipped = None, "--no-twofa"
    else:
        twofa, skipped = load_twofa(args.twofa_file, args.twofa_cache)
    now = datetime.now(timezone.utc)
    today = f"{now.astimezone():%Y-%m-%d}"
    stamp = f"{now.astimezone():%Y-%m-%d %H:%M}"  # on both pages, so a summary and a report from two runs are told apart
    rep = build(items, order, folders, not args.no_hibp, twofa, skipped, now)
    summary = render_summary(rep, stamp, args.user) if args.summary else ""
    if args.summary_only:
        write_page(args.summary, summary)
        return
    state = Path(args.state) if args.state else None
    progress = compare(read_state(state) if state else None, rep)
    report = render(rep, progress, vault_url, stamp, args.paste_line, args.user)
    if args.out:
        write_page(args.out, report)
    else:
        print(report)
    if args.summary:  # written after the report, so a failed report never leaves a summary from a newer run beside it
        write_page(args.summary, summary)
    if state:
        write_state(state, rep, today)


if __name__ == "__main__":
    main()
