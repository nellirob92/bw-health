#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Trash or merge duplicate logins in a Bitwarden vault, add https:// addresses, or merge or rename chosen entries.

A duplicate group is the same site and username (case-insensitive), the grouping the health
report uses. A site is a web address's registrable domain, taken from the public suffix list
beside this script, so secure05.bank.com and www.bank.com are bank.com while a.github.io and
b.github.io stay two sites. An IP address, localhost, a name without a dot and an app address
are each a site of their own. Four stages, each run on its own:

  exact    groups whose copies are identical in every field: keep one, trash the rest.
  merge    every group that is safe to merge: the identical ones, and those with the same password
           (or a missing one) but other details that differ. The kept copy gains the extra URLs,
           notes, custom fields and one-time-code seed, and a missing password, then the rest go
           to the trash.
  pick     groups whose only conflict is different passwords: the person picks, group by group, the
           password that works (copies listed newest password first, Enter skips), then it is merged
           like the merge stage and the other copies, with their passwords, go to the trash.
  fixurls  logins saved with only http:// addresses: each gains the https:// twin of every address,
           with the same match setting. Nothing else changes and nothing is trashed.

A copy that holds a passkey is always the kept copy, since a passkey cannot be moved; otherwise the
newest copy is kept. After every edit the item is read back, and the run stops before trashing
anything if bw saved something other than what was sent. A group is left alone, and listed with the
reason, when copies have different one-time-code seeds, a custom field with two values, an
attachment, several passkeys or one listed without its key, password history the kept copy lacks
(bw edit cannot save a joined history), or belong to an organization. fixurls leaves alone a login
that holds a passkey (an edit rewrites the whole login), one shared with an organization, and one
whose addresses are devices at home. Without --apply this only writes a plan. Trashed copies stay
in the web vault's Trash for 30 days; this script never deletes permanently.

Two steps act on entries the person names, each by its id (8 characters or more) or a search of
names, usernames and addresses that finds exactly one live login:

  merge-entries  the first entry is kept and gains what the others add, as in the merge stage, then
                 the others go to the trash. Its password stays, even when the others' differ; every
                 other reason a group is left alone still refuses, and so do different usernames.
  rename         one entry gets a new name; nothing else changes.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from urllib.parse import urlparse

LOGIN_TYPE = 1
CONFIRM_WORD = "DEDUPE"
FIXURLS_WORD = "FIXURLS"
MERGE_WORD = "MERGE"
RENAME_WORD = "RENAME"
ID_PREFIX = 8  # the shortest start of an item id taken as an id, and the length a candidate's id is shown at
MAX_LISTED = 20  # candidates listed for a search that finds several
SUFFIX_LIST = Path(__file__).with_name("public_suffix_list.dat")
SUFFIX_LIST_MIN_RULES = 5000  # the real list has about 10,000; far fewer means a cut-off or wrong file
WEB_SCHEMES = ("http", "https")
NOTE_SEPARATOR = "\n\n--- merged from a duplicate entry ---\n\n"
DIFFERENT_PASSWORDS = "different passwords"
MASKED_COPY = "a copy's username is masked with *"  # the pick stage handles it: never merged on its own
MASK = "*"
WEB_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")  # labels, none empty


def run_bw(*args: str, stdin: str | None = None) -> str:
    try:
        done = subprocess.run(["bw", *args], input=stdin, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        sys.exit("bw CLI not found. Install it: brew install bitwarden-cli")
    if done.returncode != 0:
        sys.exit(f"bw {' '.join(args)} failed:\n{done.stderr.strip() or done.stdout.strip()}")
    return done.stdout


def load_items() -> list[dict]:
    if not os.environ.get("BW_SESSION"):
        sys.exit('Vault is locked. Run:  export BW_SESSION="$(bw unlock --raw)"  then try again.')
    if json.loads(run_bw("status")).get("status") != "unlocked":
        sys.exit("Vault is not unlocked. Run: bw login, then export BW_SESSION=\"$(bw unlock --raw)\"")
    run_bw("sync")
    items = json.loads(run_bw("list", "items"))
    # bw leaves organizationId off a personal item, so a vault where no item carries it is all personal only
    # when the account is in no organization; otherwise shared items cannot be told apart.
    if items and not any("organizationId" in i for i in items) and json.loads(run_bw("list", "organizations")):
        sys.exit("bw did not say which items belong to an organization, and this account is in one, so shared items "
                 "cannot be told apart. Nothing was changed.")
    return items


def load_folders() -> dict[str, str]:
    return {f["id"]: f.get("name") or "" for f in json.loads(run_bw("list", "folders")) if f.get("id")}


def ascii_host(name: str) -> str:
    """A host name in the list's comparison form: lower case, each non-ASCII label as punycode."""
    return ".".join(label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
                    for label in name.strip(".").lower().split("."))


@dataclass(frozen=True)
class SuffixList:
    """The public suffix list (publicsuffix.org): which endings are shared, like com, co.uk or github.io."""
    rules: frozenset[str]
    wildcards: frozenset[str]   # "*.ck" is kept as "ck"
    exceptions: frozenset[str]  # "!www.ck" is kept as "www.ck"

    def registrable(self, host: str) -> str:
        """The shared ending plus one label: secure05.bank.com is bank.com, login.shop.co.uk is shop.co.uk,
        a.github.io stays a.github.io. A host that is itself a shared ending stands for itself."""
        labels = host.split(".")
        for i in range(len(labels)):  # longest candidate first, so the longest rule wins
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                size = len(labels) - i - 1
            elif candidate in self.rules or (i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wildcards):
                size = len(labels) - i
            else:
                continue
            return host if size >= len(labels) else ".".join(labels[-(size + 1):])
        return ".".join(labels[-2:])  # the list's default rule: an unlisted ending is one label


@cache
def suffix_list() -> SuffixList:
    try:
        text = SUFFIX_LIST.read_text(encoding="utf-8")
    except OSError as err:
        sys.exit(f"The public suffix list could not be read ({err}). It must sit beside {Path(__file__).name}.")
    rules, wildcards, exceptions = set(), set(), set()
    for line in text.splitlines():
        rule = line.strip().split(" ")[0]
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exceptions.add(ascii_host(rule[1:]))
        elif rule.startswith("*."):
            wildcards.add(ascii_host(rule[2:]))
        else:
            rules.add(ascii_host(rule))
    if len(rules) < SUFFIX_LIST_MIN_RULES:
        sys.exit(f"{SUFFIX_LIST} holds only {len(rules)} rules, so it is not the whole public suffix list. Nothing was changed.")
    return SuffixList(frozenset(rules), frozenset(wildcards), frozenset(exceptions))


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def parse_uri(uri: str) -> tuple[str, str, int | None] | None:
    """(scheme, host, port) of a saved address, a bare one read as https; None when it has no host or is malformed."""
    raw = uri.strip()
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host, port = (parsed.hostname or "").lower(), parsed.port
    except ValueError:  # real vaults hold malformed URLs (an unclosed IPv6 bracket); one must not stop the run
        return None
    return (parsed.scheme.lower(), host, port) if host else None


HOME_NETWORK_ENDINGS = (".local", ".lan", ".home", ".home.arpa", ".internal")


def is_device(host: str) -> bool:
    """An address that is a device, not a website: an IP address, localhost, a name without a dot, or a home-network name."""
    return is_ip(host) or host == "localhost" or "." not in host or host.endswith(HOME_NETWORK_ENDINGS)


def is_web_address(uri: str) -> bool:
    """An address a browser can open: http://, https:// or no scheme, and a host that is a device or whole labels."""
    parts = parse_uri(uri)
    return parts is not None and parts[0] in WEB_SCHEMES and (is_device(parts[1]) or bool(WEB_HOST.fullmatch(ascii_host(parts[1]))))


def broken_web_address(uri: str) -> bool:
    """Written as a web address (http://, https:// or no scheme) but not one: a host like ".something", or malformed."""
    raw = uri.strip().lower()
    return (raw.split("://", 1)[0] if "://" in raw else "https") in WEB_SCHEMES and not is_web_address(uri)


def site_of(uri: str) -> str:
    """The site a saved address belongs to. A web address is its registrable domain, without www. or a page;
    a device keeps its host and port, never split into labels; an app, malformed or broken address is itself."""
    if not is_web_address(uri):
        return uri.strip().lower().rstrip("/")
    _, host, port = parse_uri(uri)
    if is_device(host):
        return host + (f":{port}" if port else "")
    return suffix_list().registrable(ascii_host(host))


def first_site_uri(uris: list[str]) -> str | None:
    """The address that names a login's site: its first web address, or its first address when it has none."""
    web = [u for u in uris if is_web_address(u)]
    return (web or uris or [None])[0]


def uri_strings(item: dict) -> list[str]:
    return [uri for u in login_of(item).get("uris") or [] if (uri := ((u or {}).get("uri") or "").strip())]


def login_of(item: dict) -> dict:
    return item.get("login") or {}


def mask_fits(masked: str, username: str) -> bool:
    """A masked username (some letters shown as *) could be this one: same length, every shown letter in its place."""
    return len(masked) == len(username) and all(m == MASK or m.lower() == c.lower() for m, c in zip(masked, username))


def account_keys(items: list[dict]) -> dict[str, str]:
    """Item id -> its account: same site + username (case-insensitive). A login missing either has none and stands alone.
    A masked username that fits exactly one unmasked username on the same site joins that account as a masked copy;
    fitting none or several, it stays its own account."""
    keys: dict[str, str] = {}
    masked: dict[str, tuple[str, str]] = {}
    plain: dict[str, set[str]] = defaultdict(set)
    for i in items:
        username = login_of(i).get("username") or ""
        first = first_site_uri(uri_strings(i))
        if i.get("type") != LOGIN_TYPE or not (first and username):
            continue
        site = site_of(first)
        keys[i["id"]] = f"{site}|{username.lower()}"
        if not i.get("deletedDate"):
            if MASK in username:
                masked[i["id"]] = (site, username)
            else:
                plain[site].add(username.lower())
    for item_id, (site, username) in masked.items():
        fits = {u for u in plain[site] if mask_fits(username, u)}
        if len(fits) == 1:
            keys[item_id] = f"{site}|{fits.pop()}"
    return keys


def is_masked_copy(item: dict, account: str) -> bool:
    """A copy whose masked username was matched to the account's unmasked one."""
    username = login_of(item).get("username") or ""
    return MASK in username and username.lower() != account.partition("|")[2]


def uri_key(u: dict, loose: bool = False) -> str:
    """Is this URL already there? With the default, domain or host match, Bitwarden autofills by site, so every address on
    one site (any scheme, www., page or query string) is one URL: Chrome stores just the site, which the kept copy
    usually already has with a login page. A starts-with or exact match depends on the full address, so there only the
    scheme-less, trailing-slash and capitals differences are ignored. loose ignores the match setting, to spot one
    address carrying two different settings. Assumes the vault's default match is the default (base domain)."""
    raw = ((u or {}).get("uri") or "").strip()
    match = (u or {}).get("match")
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host, port = (parsed.hostname or "").lower(), parsed.port
    except ValueError:  # a malformed URL stands for itself
        return raw.rstrip("/")
    if not host:
        return raw.rstrip("/")
    scheme = parsed.scheme.lower()
    keep_scheme = scheme not in ("http", "https") or (not loose and match in (2, 3))
    host = host[4:] if host.startswith("www.") else host
    if not loose and match in (None, 0, 1) and scheme in ("http", "https"):
        return host + (f":{port}" if port else "")
    return ((f"{scheme}://" if keep_scheme else "") + host + (f":{port}" if port else "")
            + parsed.path.rstrip("/") + (f"?{parsed.query}" if parsed.query else ""))


def field_key(f: dict) -> tuple:
    """All strings, so a missing value sorts next to a present one instead of raising."""
    return tuple(str(f.get(k)) for k in ("name", "value", "type", "linkedId"))


def clean(text: str) -> str:
    """Safe in one plan-table cell and on the terminal: no control characters, no pipe."""
    return "".join(" " if c in "\r\n\t" else "/" if c == "|" else c for c in text if c.isprintable() or c in "\r\n\t")


def fingerprint(item: dict) -> str:
    """Every field a person could notice differing; two items with one fingerprint are 100% copies."""
    login = login_of(item)
    return json.dumps([
        item.get("name") or "", login.get("username") or "", login.get("password") or "",
        sorted((str(u.get("match")), u.get("uri") or "") for u in login.get("uris") or []),
        item.get("notes") or "", login.get("totp") or "",
        sorted(field_key(f) for f in item.get("fields") or []),
        item.get("folderId"), bool(item.get("favorite")), item.get("reprompt") or 0,
        item.get("passwordHistory") or [],
    ], sort_keys=True, default=str)


def passkeys(item: dict) -> list[dict]:
    return login_of(item).get("fido2Credentials") or []


def passkey_ids(item: dict) -> list[tuple[str, str]]:
    """Each passkey's id and a hash of its key material, so two items can be compared without showing the key."""
    return sorted((str(c.get("credentialId")), hashlib.sha256(str(c.get("keyValue")).encode("utf-8")).hexdigest(),
                   str(c.get("rpId")), str(c.get("userHandle")))
                  for c in passkeys(item))


def key_missing(item: dict) -> bool:
    """A passkey bw listed without its key: an edit would save the gap, and a read-back of a gap proves nothing."""
    return any(not c.get("keyValue") or not c.get("credentialId") or not c.get("rpId") for c in passkeys(item))


def blocker(items: list[dict], keeper: dict, masked: list[dict]) -> str | None:
    """Why this group must be left alone, or None when it is safe to act on."""
    if any(i.get("organizationId") for i in items):
        return "shared with an organization"
    if any(i.get("attachments") for i in items):
        return "has an attachment"
    if sum(1 for i in items if passkeys(i)) > 1:
        return "several copies hold a passkey"
    if any(key_missing(i) for i in items):
        return "a passkey that bw listed without its key"
    if len({login_of(i).get("totp") for i in items if login_of(i).get("totp")}) > 1:
        return "different one-time-code seeds"
    seen: dict[tuple, str] = {}
    for i in items:
        for f in i.get("fields") or []:
            if seen.setdefault((f.get("name"), f.get("type")), f.get("value")) != f.get("value"):
                return "a custom field with different values"
    if any(passkeys(i) for i in masked):
        return "the copy with a masked username holds a passkey"  # the kept copy must be the passkey's, with the masked name
    # bw edit keeps the item's own password history and discards the history it is sent, so a copy's history cannot be carried over
    kept_history = {json.dumps(h, sort_keys=True) for h in keeper.get("passwordHistory") or []}
    if any(json.dumps(h, sort_keys=True) not in kept_history
           for i in items if i is not keeper for h in i.get("passwordHistory") or []):
        return "a copy has password history the kept copy lacks"
    matches: dict[str, set[str]] = {}
    for i in items:
        for u in login_of(i).get("uris") or []:
            matches.setdefault(uri_key(u, loose=True), set()).add(str(u.get("match")))
    if any(len(m) > 1 for m in matches.values()):
        return "the same URL with different match settings"
    if masked:
        return MASKED_COPY  # the pick stage handles it, as it does different passwords: a person decides
    if len({pw for i in items if (pw := login_of(i).get("password"))}) > 1:  # an empty password is a gap, not a conflict
        return DIFFERENT_PASSWORDS  # checked last, so this reason means the pick stage can handle the group
    return None


PICK_REASONS = (DIFFERENT_PASSWORDS, MASKED_COPY)


def pick_keeper(items: list[dict]) -> dict:
    """The copy that holds a passkey (it cannot be moved to another item), otherwise the newest copy."""
    holders = [i for i in items if passkeys(i)]
    if holders:
        return holders[0]
    return max(items, key=lambda i: (i.get("revisionDate") or "", i["id"]))


def merge_into(keeper: dict, others: list[dict]) -> dict:
    """The keeper plus everything the others add. Only ever adds, so trashed copies lose nothing."""
    merged = copy.deepcopy(keeper)
    login = merged.setdefault("login", {})
    uris = login.setdefault("uris", []) or []
    login["uris"] = uris
    seen_uris = {uri_key(u) for u in uris}
    seen_fields = {field_key(f) for f in merged.get("fields") or []}
    notes = [n for n in [(keeper.get("notes") or "").strip()] if n]
    if not login.get("password"):  # one distinct password among the copies, or the pick stage sets the chosen one after
        filled = next((login_of(o)["password"] for o in others if login_of(o).get("password")), None)
        if filled:
            login["password"] = filled
    for other in others:
        for u in login_of(other).get("uris") or []:
            if uri_key(u) and uri_key(u) not in seen_uris:
                uris.append(u)
                seen_uris.add(uri_key(u))
        for f in other.get("fields") or []:
            if field_key(f) not in seen_fields:
                merged.setdefault("fields", []).append(f)
                seen_fields.add(field_key(f))
        note = (other.get("notes") or "").strip()
        if note and not any(note in n for n in notes):
            notes = [n for n in notes if n not in note] + [note]
        if not login.get("totp") and login_of(other).get("totp"):
            login["totp"] = login_of(other)["totp"]
        merged["favorite"] = bool(merged.get("favorite") or other.get("favorite"))
        merged["reprompt"] = max(merged.get("reprompt") or 0, other.get("reprompt") or 0)
    if notes:
        merged["notes"] = NOTE_SEPARATOR.join(notes)
    return merged


@dataclass
class Group:
    account: str
    keeper: dict
    others: list[dict]
    merged: dict | None = None      # the keeper to save, or None when it needs no edit
    exact: bool = False
    blocked: str | None = None

    @property
    def label(self) -> str:
        host, user = self.account.split("|", 1)
        return clean(f"{host} ({user})")


def find_groups(items: list[dict]) -> list[Group]:
    keys = account_keys(items)
    by_account: dict[str, list[dict]] = {}
    for i in items:
        if i.get("type") == LOGIN_TYPE and not i.get("deletedDate") and i["id"] in keys:
            by_account.setdefault(keys[i["id"]], []).append(i)
    groups = []
    for account, members in sorted(by_account.items()):
        if len(members) < 2:
            continue
        masked = [m for m in members if is_masked_copy(m, account)]
        keeper = pick_keeper([m for m in members if m not in masked])  # the kept copy keeps the real username
        others = [m for m in members if m["id"] != keeper["id"]]
        g = Group(account, keeper, others, blocked=blocker(members, keeper, masked))
        g.exact = len({fingerprint(m) for m in members}) == 1
        if not g.blocked and not g.exact:
            merged = merge_into(keeper, others)
            g.merged = merged if merged != keeper else None
        groups.append(g)
    return groups


def http_only(uris: list[str]) -> bool:
    """Every saved address starts with http://: the case the report flags for AutoFill."""
    return bool(uris) and all(u.lower().startswith("http://") for u in uris)


def on_devices(uris: list[str]) -> bool:
    """Every address is a device at home (a router, a printer), which has no https:// page to add."""
    return all((p := parse_uri(u)) is not None and is_device(p[1]) for u in uris)


def https_twin(u: dict) -> dict:
    """The same address and match setting over https://. Only ever called on an http:// address."""
    uri = (u.get("uri") or "").strip()
    return {**u, "uri": "https://" + uri[len("http://"):]}


def find_fixes(items: list[dict]) -> tuple[list[Group], list[Group]]:
    """(logins to fix, logins left alone with the reason). A fix is a Group with no other copies."""
    fixes, left = [], []
    for i in items:
        if i.get("type") != LOGIN_TYPE or i.get("deletedDate") or not http_only(uri_strings(i)) or on_devices(uri_strings(i)):
            continue
        username = login_of(i).get("username") or ""
        g = Group(f"{site_of(uri_strings(i)[0])}|{username.lower()}", i, [])
        if i.get("organizationId"):
            g.blocked = "shared with an organization"
        elif passkeys(i):
            g.blocked = "holds a passkey: add its https:// address by hand in Bitwarden"
        elif any(broken_web_address(u) for u in uri_strings(i)):
            g.blocked = "an address that isn't a web address: correct it by hand in Bitwarden"
        else:  # a device's address (a router beside the website) gets no https:// twin
            merged = copy.deepcopy(i)
            uris = login_of(merged)["uris"]
            uris += [https_twin(u) for u in list(uris) if (p := parse_uri((u or {}).get("uri") or "")) and not is_device(p[1])]
            g.merged = merged
        (left if g.blocked else fixes).append(g)
    return fixes, left


def select(groups: list[Group], stage: str) -> tuple[list[Group], list[Group], int]:
    """(groups this stage acts on, groups left alone, groups waiting for another stage)."""
    if stage == "pick":
        acting = [g for g in groups if g.blocked in PICK_REASONS]
        blocked = [g for g in groups if g.blocked and g.blocked not in PICK_REASONS]
    else:  # merge takes every group that is safe to merge, the identical ones included
        acting = [g for g in groups if not g.blocked and (stage == "merge" or g.exact)]
        blocked = [g for g in groups if g.blocked]
    other_stage = len(groups) - len(acting) - len(blocked)
    return acting, blocked, other_stage


def when(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def item_dates(item: dict) -> list[tuple[str, datetime | None]]:
    return [("password changed", when(login_of(item).get("passwordRevisionDate"))),
            ("edited", when(item.get("revisionDate"))), ("created", when(item.get("creationDate")))]


def shown_dates(item: dict) -> str:
    """Every date bw reports for a copy, in local time."""
    return ", ".join(f"{label} {d.astimezone():%Y-%m-%d %H:%M}" for label, d in item_dates(item) if d)


def by_newest_password(g: Group) -> list[dict]:
    """The group's copies, newest password first. A password is as old as its last change, or as its copy when
    bw has never seen it change (an import or an untouched entry); the last edit breaks ties."""
    oldest = datetime.min.replace(tzinfo=timezone.utc)

    def key(item: dict) -> tuple:
        changed, edited, created = (d for _, d in item_dates(item))
        return (changed or created or oldest, edited or oldest, item["id"])
    return sorted([g.keeper, *g.others], key=key, reverse=True)


def set_password(g: Group, password: str) -> None:
    """The keeper with the chosen password and everything the merge stage would add."""
    merged = merge_into(g.keeper, g.others)
    merged["login"]["password"] = password
    g.merged = merged if merged != g.keeper else None


STAGE_SUMMARY = {
    "exact": ("Exact stage: a login saved more than once (same site and username) where the copies are identical in every field. "
              "One copy is kept and the rest go to the Bitwarden trash."),
    "merge": ("Merge stage: a login saved more than once (same site and username) with the same password, or a missing one. "
              "The kept copy gains the other copies' URLs, "
              "notes, custom fields, one-time-code seed, a missing password and any favorite or re-prompt setting, then the rest go to the "
              "Bitwarden trash. A copy with a passkey is always the one kept, otherwise the newest. Only the kept copy's name and folder survive."),
    "pick": ("Pick stage: a login saved more than once (same site and username) whose copies have different passwords and "
             "no other conflict. Each copy is listed newest password first, with its dates. Type the number of the password "
             "that works, or press Enter to skip the group. The kept entry takes that password and gains the other copies' "
             "details as in the merge stage. The other copies, with their passwords, go to the Bitwarden trash for 30 days. "
             "A copy with a passkey is always the one kept."),
    "fixurls": ("AutoFill fix: a login saved with only http:// addresses gains the https:// twin of each one, with the same match "
                "setting, so AutoFill can offer it on the secure page. Nothing else in the entry changes and nothing goes to the trash. "
                "A login that holds a passkey is left alone, because the edit rewrites the whole login: add its https:// address by hand."),
}


def shown_url(u: dict) -> str:
    """A URL for display: no query string or fragment (they can carry tokens), no control characters, short."""
    text = clean(((u or {}).get("uri") or "").split("?")[0].split("#")[0])
    return text if len(text) <= 80 else text[:77] + "..."


def gains(g: Group) -> list[str]:
    """What the kept copy gains from the others (empty when the group needs no edit)."""
    kept = g.merged or g.keeper
    have = {uri_key(u) for u in login_of(g.keeper).get("uris") or []}
    new_urls = [shown_url(u) for u in login_of(kept).get("uris") or [] if uri_key(u) not in have]
    out = []
    if new_urls:
        out.append(f"+{len(new_urls)} URL ({', '.join(new_urls)})")
    n_fields = len(kept.get("fields") or []) - len(g.keeper.get("fields") or [])
    if n_fields:
        out.append(f"+{n_fields} custom field")
    if (kept.get("notes") or "") != (g.keeper.get("notes") or ""):
        out.append("notes joined")
    if login_of(kept).get("totp") != login_of(g.keeper).get("totp"):
        out.append("one-time-code seed taken")
    if login_of(kept).get("password") != login_of(g.keeper).get("password"):
        out.append("password taken from another copy")
    if bool(kept.get("favorite")) != bool(g.keeper.get("favorite")):
        out.append("marked favorite")
    if (kept.get("reprompt") or 0) != (g.keeper.get("reprompt") or 0):
        out.append("master password re-prompt turned on")
    return out


def differences(g: Group) -> list[str]:
    """What the trashed copies had that cannot be kept: a name or a folder (an item lives in one folder)."""
    out = []
    if any(o.get("name") != g.keeper.get("name") for o in g.others):
        out.append("names differ, the kept name wins")
    if any(o.get("folderId") != g.keeper.get("folderId") for o in g.others):
        out.append("folders differ, the kept folder wins")
    return out


def describe_change(g: Group) -> str:
    return ", ".join(gains(g) + differences(g)) or "nothing to add"


def planned_change(g: Group, stage: str) -> str:
    """describe_change for the plan file. A pick group's password is chosen only at apply, so the plan shows the rest."""
    if stage != "pick":
        return describe_change(g)
    merged = merge_into(g.keeper, g.others)
    merged["login"]["password"] = login_of(g.keeper).get("password")
    return "the password you choose; " + describe_change(Group(g.account, g.keeper, g.others, merged=merged))


def folder_name(item: dict, folders: dict[str, str]) -> str:
    fid = item.get("folderId")
    return clean(folders.get(fid) or "unknown folder") if fid else "no folder"


def item_summary(item: dict, folders: dict[str, str]) -> str:
    n = len(login_of(item).get("uris") or [])
    return f'"{clean(item.get("name") or "(no name)")}"  folder: {folder_name(item, folders)}  {n} URL{"" if n == 1 else "s"}'


def render_preview(groups: list[Group], total: int, folders: dict[str, str]) -> str:
    """Each group as the vault will see it: the copy kept, the copies trashed, what is added."""
    lines = []
    for n, g in enumerate(groups, start=1):
        lines += [f"[{n}/{total}] {g.label}, {len(g.others) + 1} copies",
                  f"  KEEP   {item_summary(g.keeper, folders)}"]
        lines += [f"  TRASH  {item_summary(o, folders)}" for o in g.others]
        lines.append(f"  ADDS   {', '.join(gains(g)) or 'nothing'}")
        if differences(g):
            lines.append(f"  NOTE   {', '.join(differences(g))}")
        if passkeys(g.keeper) and g.merged is not None:  # with no edit the passkey copy is never written
            lines.append("  NOTE   the kept copy holds a passkey. The edit is read back and the run stops before trashing if it differs, "
                         "but the passkey itself could already be changed: keep the original in Apple Passwords or Chrome until you have checked this entry in Bitwarden")
        lines.append("")
    return "\n".join(lines)


def addresses(item: dict) -> str:
    """A copy's hosts, without www., a page or a query string (it can carry a token)."""
    hosts = []
    for u in uri_strings(item):
        p = parse_uri(u)
        host = (p[1][4:] if p[1].startswith("www.") else p[1]) + (f":{p[2]}" if p[2] else "") if p and p[0] in WEB_SCHEMES else clean(u.split("?")[0])
        hosts += [host] if host not in hosts else []
    return ", ".join(hosts) or "no address"


def may_be_separate(g: Group) -> bool:
    """Copies saved for different addresses on one site, or under a masked username, may be two accounts, not one."""
    return g.blocked == MASKED_COPY or len({addresses(i) for i in [g.keeper, *g.others]}) > 1


def render_choices(g: Group, copies: list[dict], n: int, total: int, folders: dict[str, str]) -> str:
    """A pick group's copies, numbered newest password first, each with its addresses and its dates in local time."""
    what = "copies, one with a masked username" if g.blocked == MASKED_COPY else "copies with different passwords"
    lines = [f"[{n}/{total}] {g.label}, {len(copies)} {what}"]
    if may_be_separate(g):
        lines.append("  These may be separate accounts. If they are, press Enter to keep both.")
    for k, item in enumerate(copies, start=1):
        dates = shown_dates(item)
        mark = "" if item is not g.keeper else "  (kept entry, holds a passkey)" if passkeys(item) else "  (kept entry)"
        masked = "  (masked username)" if is_masked_copy(item, g.account) else ""
        lines.append(f'  {k}  "{clean(item.get("name") or "(no name)")}"  {addresses(item)}  folder: {folder_name(item, folders)}  '
                     f'{dates}{mark}{masked}')
    return "\n".join(lines)


def choose_passwords(groups: list[Group], folders: dict[str, str]) -> list[Group]:
    """Asks, group by group, which copy's password works. Enter keeps both; anything but a listed number skips the group."""
    chosen = []
    for n, g in enumerate(groups, start=1):
        copies = by_newest_password(g)
        print(render_choices(g, copies, n, len(groups), folders))
        answer = ask("Type the number of the copy whose password works (1 is the newest; the number, not the password), "
                     "or press Enter to keep both as they are: ")
        if not answer:
            print("Kept both. Nothing changes for this group.\n")
        elif answer not in {str(k) for k in range(1, len(copies) + 1)}:
            print("That is not one of the numbers shown, so this group is skipped.\n")  # never echoed: it could be a password
        elif not login_of(copies[int(answer) - 1]).get("password"):
            print("That copy has no password, so this group is skipped.\n")
        else:
            set_password(g, login_of(copies[int(answer) - 1])["password"])
            chosen.append(g)
            print()
    return chosen


def render_plan(stage: str, acting: list[Group], blocked: list[Group], other_stage: int, folders: dict[str, str]) -> str:
    trash = sum(len(g.others) for g in acting)
    lines = [f"# Duplicate cleanup plan: {stage}", "", STAGE_SUMMARY[stage], "",
             f"- Groups this stage will change: **{len(acting)}** ({trash} copies to the trash)",
             f"- Groups left alone: **{len(blocked)}**",
             f"- Groups for another stage: **{other_stage}**", ""]
    lines += ["## Will change", ""]
    if acting:
        lines += ["| Account | Copies | Kept | Trashed | What the kept copy gains |", "| --- | --- | --- | --- | --- |"]
        lines += [f"| {g.label} | {len(g.others) + 1} "
                  f"| {clean(g.keeper.get('name') or '(no name)')} ({folder_name(g.keeper, folders)}) "
                  f"| {'; '.join(clean(o.get('name') or '(no name)') + ' (' + folder_name(o, folders) + ')' for o in g.others)} "
                  f"| {planned_change(g, stage)} |"
                  for g in acting]
    else:
        lines.append("Nothing.")
    lines += ["", "## Left alone, and why", ""]
    if blocked:
        lines += ["| Account | Copies | Reason |", "| --- | --- | --- |"]
        lines += [f"| {g.label} | {len(g.others) + 1} | {g.blocked} |" for g in blocked]
    else:
        lines.append("Nothing.")
    lines += ["", "_No password is written in this file._"]
    return "\n".join(lines)


def added_urls(g: Group) -> list[str]:
    """The https:// addresses a fixurls edit adds, for display."""
    have = {(u or {}).get("uri") for u in login_of(g.keeper).get("uris") or []}
    return [shown_url(u) for u in login_of(g.merged or g.keeper).get("uris") or [] if u.get("uri") not in have]


def render_fixes(fixes: list[Group], total: int, folders: dict[str, str]) -> str:
    lines = []
    for n, g in enumerate(fixes, start=1):
        lines += [f"[{n}/{total}] {g.label}", f"  ENTRY  {item_summary(g.keeper, folders)}",
                  f"  ADDS   {', '.join(added_urls(g))}", ""]
    return "\n".join(lines)


def render_fix_plan(fixes: list[Group], left: list[Group], folders: dict[str, str]) -> str:
    lines = ["# AutoFill fix plan", "", STAGE_SUMMARY["fixurls"], "",
             f"- Logins this step will change: **{len(fixes)}**", f"- Logins left alone: **{len(left)}**", "", "## Will change", ""]
    if fixes:
        lines += ["| Login | Entry | Adds |", "| --- | --- | --- |"]
        lines += [f"| {g.label} | {clean(g.keeper.get('name') or '(no name)')} ({folder_name(g.keeper, folders)}) "
                  f"| {', '.join(added_urls(g))} |" for g in fixes]
    else:
        lines.append("Nothing.")
    lines += ["", "## Left alone, and why", ""]
    if left:
        lines += ["| Login | Reason |", "| --- | --- |"] + [f"| {g.label} | {g.blocked} |" for g in left]
    else:
        lines.append("Nothing.")
    lines += ["", "_No password is written in this file._"]
    return "\n".join(lines)


@cache
def terminal():
    """Opened once, so successive answers are successive lines (stdin is not the keyboard under curl | bash)."""
    return open(os.environ.get("BW_HEALTH_TTY", "/dev/tty"), encoding="utf-8")


def ask(prompt: str) -> str:
    print(prompt, end="", flush=True)
    return terminal().readline().strip()


def verify_edit(g: Group, exact_uris: bool = False) -> None:
    """Read the kept copy back after the edit. Stops the run, before anything is trashed, if bw saved something other
    than what was sent: a passkey cannot be recreated, and the real edit path has been seen to rebuild the login.
    exact_uris: every address sent must come back as written (the https:// twin is the whole point of fixurls)."""
    got = json.loads(run_bw("get", "item", g.keeper["id"]))
    want = g.merged or g.keeper
    wrong = []
    if exact_uris and ({(u.get("uri"), u.get("match")) for u in login_of(want).get("uris") or []}
                       - {(u.get("uri"), u.get("match")) for u in login_of(got).get("uris") or []}):
        wrong.append("web addresses")
    if login_of(got).get("password") != login_of(want).get("password"):
        wrong.append("password")
    if passkey_ids(got) != passkey_ids(want):
        wrong.append("passkey")
    if {uri_key(u) for u in login_of(want).get("uris") or []} - {uri_key(u) for u in login_of(got).get("uris") or []}:
        wrong.append("URLs")
    if (got.get("notes") or "").replace("\r\n", "\n").strip() != (want.get("notes") or "").replace("\r\n", "\n").strip():
        wrong.append("notes")
    if login_of(got).get("totp") != login_of(want).get("totp"):
        wrong.append("one-time-code seed")
    if len(got.get("passwordHistory") or []) < len(want.get("passwordHistory") or []):
        wrong.append("password history")  # bw may add entries (a changed password), never lose the item's own
    if sorted(field_key(f) for f in got.get("fields") or []) != sorted(field_key(f) for f in want.get("fields") or []):
        wrong.append("custom fields")
    if (got.get("name"), got.get("folderId")) != (want.get("name"), want.get("folderId")):
        wrong.append("name or folder")
    if (bool(got.get("favorite")), got.get("reprompt") or 0) != (bool(want.get("favorite")), want.get("reprompt") or 0):
        wrong.append("favorite or re-prompt setting")
    if wrong:
        sys.exit(f"Stopped after editing {g.label}: bw saved a different {', '.join(wrong)} than was sent. "
                 "Nothing in this group was trashed and no later group was touched, but the kept entry itself may already be "
                 "changed (a passkey that was changed cannot be recreated from Bitwarden). "
                 "Do not delete the original entries in Apple Passwords or Chrome; check this entry in the Bitwarden web vault "
                 "and tell the person who sent you this line what this window printed.")


def apply(groups: list[Group], fixurls: bool = False) -> None:
    for g in groups:  # checked up front so a refusal changes nothing
        if any(str(i["id"]).startswith("-") for i in [g.keeper, *g.others]):
            sys.exit(f"Refusing {g.label}: an item id starts with '-', which bw could read as an option. Nothing was changed.")
    for n, g in enumerate(groups, start=1):
        if g.merged is not None:
            encoded = base64.b64encode(json.dumps(g.merged).encode("utf-8")).decode("ascii")
            run_bw("edit", "item", g.keeper["id"], stdin=encoded)
            verify_edit(g, exact_uris=fixurls)
        for other in g.others:
            run_bw("delete", "item", other["id"])
        # a rename is the one edit with no other copies, outside fixurls
        done = "added the https:// address" if fixurls else f"kept one, trashed {len(g.others)}" if g.others else "renamed"
        print(f"[{n}/{len(groups)}] {g.label}: {done}", flush=True)


def run_fixurls(args: argparse.Namespace, items: list[dict], folders: dict[str, str], out_dir: Path) -> None:
    fixes, left = find_fixes(items)
    plan = out_dir / "plan-fixurls.md"
    plan.write_text(render_fix_plan(fixes, left, folders), encoding="utf-8")
    plan.chmod(0o600)
    print(f"{len(fixes)} login(s) to change, {len(left)} left alone. Plan: {plan}")
    print(f"\n{STAGE_SUMMARY['fixurls']}")
    if left:
        print("Left alone: " + ", ".join(f"{n} {why}" for why, n in Counter(g.blocked for g in left).most_common()) + ".")
    if not args.apply:
        if fixes[:3]:
            head = "all" if len(fixes) <= 3 else f"the first 3 of {len(fixes)}"
            print(f"\nPreview: {head} logins (every login is in the plan file)\n")
            print(render_fixes(fixes[:3], len(fixes), folders))
        print("Nothing was changed. Add apply to act on this plan.")
        return
    todo = fixes[: args.limit] if args.limit else fixes
    if not todo:
        print("Nothing to do.")
        return
    print(f"\nActing on {len(todo)} of {len(fixes)} logins:\n")
    print(render_fixes(todo, len(todo), folders))
    answer = ask(f"This will add an https:// address to {len(todo)} {'login' if len(todo) == 1 else 'logins'} and change nothing else. "
                 f"Type {FIXURLS_WORD} to continue: ")
    if answer != FIXURLS_WORD:
        sys.exit("Not confirmed. Nothing was changed.")
    apply(todo, fixurls=True)
    print("Done. Run the check-up again to see what is left.")


def found_by(item: dict, term: str) -> bool:
    """The term is in the entry's name, username or one of its addresses, any capitals."""
    t = term.lower()
    return any(t in text.lower() for text in [item.get("name") or "", login_of(item).get("username") or "", *uri_strings(item)])


def candidate_line(item: dict, width: int) -> str:
    """One entry a search found: the start of its id, name, username and addresses. Never a password."""
    return clean(f'  {str(item["id"])[:width]}  "{item.get("name") or "(no name)"}"  '
                 f'{login_of(item).get("username") or "(no username)"}  {addresses(item)}')


def pick_entries(items: list[dict], terms: list[str]) -> list[dict]:
    """The one live login each term names: the login with that id, else the logins whose id starts with it (8 characters
    or more) or that it finds by name, username or address. Stops the run, listing what each term found, unless every
    term finds exactly one."""
    logins = [i for i in items if i.get("type") == LOGIN_TYPE and not i.get("deletedDate")]
    found, missing, several = [], [], []
    for term in terms:
        hits = [i for i in logins if str(i["id"]).lower() == term.lower()] or [
            i for i in logins if (len(term) >= ID_PREFIX and str(i["id"]).lower().startswith(term.lower())) or found_by(i, term)]
        if len(hits) == 1:
            found.append(hits[0])
        elif not hits:
            missing.append(f'No login in your vault matches "{clean(term)}" by name, username, web address or id.')
        else:
            width = ID_PREFIX  # long enough to tell these candidates apart, so the id shown always finds one
            while len({str(i["id"])[:width] for i in hits}) < len(hits) and width < max(len(str(i["id"])) for i in hits):
                width += 1
            lines = [f'"{clean(term)}" matches {len(hits)} logins:'] + [candidate_line(i, width) for i in hits[:MAX_LISTED]]
            if len(hits) > MAX_LISTED:
                lines.append(f"  ... and {len(hits) - MAX_LISTED} more. Search for something longer, or use the id.")
            several.append("\n".join(lines))
    if missing or several:
        advice = ["Nothing was changed."]
        if several:
            advice.append("Run the line again with the id of the entry you mean: the characters at the start of its line above.")
        if missing:
            advice.append("Check the spelling, or use the entry's id, from the address of the entry in the Bitwarden web vault.")
        sys.exit("\n\n".join(missing + several + [" ".join(advice)]))
    return found


def account_of(item: dict) -> str:
    """The site and username a chosen entry is shown under, as a group's account is."""
    first = first_site_uri(uri_strings(item))
    return f"{site_of(first) if first else 'no address'}|{login_of(item).get('username') or '(no username)'}"


def merge_refusal(keeper: dict, others: list[dict]) -> str | None:
    """Why these chosen entries must not be merged, or None. The person chose the entry to keep, so its password may
    differ from the others'; every other reason the duplicate cleanup leaves a group alone still refuses."""
    def username(i: dict) -> str:
        return (login_of(i).get("username") or "").strip().lower()
    odd = [o for o in others if username(o) != username(keeper)]
    if odd:
        # A masked username can fit a different account on the same site: only dedupe pick, which says so, may join it.
        if any(MASK in (login_of(i).get("username") or "") for i in [keeper, *odd]):
            return (f"{MASKED_COPY}, so it may be a different account. Type the real username in that entry in Bitwarden "
                    "first, or use dedupe pick, which shows both copies")
        return "the usernames differ (" + ", ".join(sorted({clean(login_of(i).get("username") or "(none)") for i in [keeper, *odd]})) + ")"
    why = blocker([keeper, *others], keeper, [])  # no masked copy: every username is the same
    if why and why != DIFFERENT_PASSWORDS:
        return why
    if any(passkeys(o) for o in others):
        return "an entry to fold in holds a passkey, which cannot be moved: run it again with that entry as the one to keep"
    if not login_of(keeper).get("password") and len({pw for o in others if (pw := login_of(o).get("password"))}) > 1:
        return "the entry to keep has no password and the others have different ones: run it again keeping the entry whose password works"
    return None


def password_lines(g: Group) -> list[str]:
    """Each entry's password as a letter, A being the kept entry's, with its dates; nothing when the passwords agree.
    Only ever shown after merge_refusal, so when they differ the kept entry has a password."""
    letters: dict[str, str] = {}
    for i in [g.keeper, *g.others]:
        if pw := login_of(i).get("password"):
            letters.setdefault(pw, chr(ord("A") + len(letters)))
    if len(letters) < 2:
        return []
    lines = ["  PASSWORDS differ. Each is shown as a letter, never the password itself:"]
    for i in [g.keeper, *g.others]:
        pw = login_of(i).get("password")
        about = ", ".join(([] if pw else ["no password"]) + ([shown_dates(i)] if shown_dates(i) else []))
        lines.append(f'    {letters[pw] if pw else "-"}  "{clean(i.get("name") or "(no name)")}"  {about}{"  (kept)" if i is g.keeper else ""}')
    dropped = sorted(set(letters.values()) - {"A"})
    which = (f"Password {dropped[0]} is dropped: it goes to the Bitwarden trash with its entry, where it stays" if len(dropped) == 1 else
             f"Passwords {', '.join(dropped)} are dropped: they go to the Bitwarden trash with their entries, where they stay")
    lines.append(f"  The kept entry keeps password A. {which} for 30 days and can be restored. "
                 "Sign in with password A before then to check that it works.")
    return lines


def run_merge(keep: str, fold: list[str]) -> None:
    print(f"Nothing in your vault changes until you have read the plan below and typed {MERGE_WORD}.\n", flush=True)
    items = load_items()
    folders = load_folders()
    keeper, *others = pick_entries(items, [keep, *fold])
    ids = [o["id"] for o in others]
    if keeper["id"] in ids:
        sys.exit(f'The entry to keep, "{clean(keeper.get("name") or "(no name)")}", is also named as an entry to fold in. Nothing was changed.')
    if len(set(ids)) < len(ids):
        sys.exit("The same entry is named twice as an entry to fold in. Nothing was changed.")
    if why := merge_refusal(keeper, others):
        sys.exit(f"Not merged: {why}. Nothing was changed.")
    merged = merge_into(keeper, others)
    g = Group(account_of(keeper), keeper, others, merged=merged if merged != keeper else None)
    print(render_preview([g], 1, folders))
    print("\n".join(password_lines(g) + [""]))
    n = len(others)
    answer = ask(f"This will {'edit the kept entry and ' if g.merged is not None else ''}move {n} {'entry' if n == 1 else 'entries'} "
                 f"to the Bitwarden trash, where {'it stays' if n == 1 else 'they stay'} for 30 days. Type {MERGE_WORD} to continue: ")
    if answer != MERGE_WORD:
        sys.exit("Not confirmed. Nothing was changed.")
    apply([g])
    print(f"Done. {n} {'entry is' if n == 1 else 'entries are'} in the web vault's Trash for 30 days.")


def rename_refusal(item: dict) -> str | None:
    """Why an entry must be renamed by hand, or None: the edit sends the whole entry back to bw."""
    if item.get("organizationId"):
        return "it is shared with an organization"
    if item.get("attachments"):
        return "it has an attachment"
    if key_missing(item):
        return "it holds a passkey that bw listed without its key"
    return None


def run_rename(entry: str, new_name: str) -> None:
    if not new_name.strip() or "\n" in new_name or "\r" in new_name:
        sys.exit("The new name must have something in it, on one line. Nothing was changed.")
    print(f"Nothing in your vault changes until you have read the change below and typed {RENAME_WORD}.\n", flush=True)
    item = pick_entries(load_items(), [entry])[0]
    if item.get("name") == new_name:
        print(f'Nothing to do: the entry is already named "{clean(new_name)}".')
        return
    if why := rename_refusal(item):
        sys.exit(f"Not renamed: {why}. Rename it in the Bitwarden web vault. Nothing was changed.")
    merged = copy.deepcopy(item)
    merged["name"] = new_name
    g = Group(account_of(item), item, [], merged=merged)
    print(f'  ENTRY  {g.label}  {addresses(item)}\n  FROM   "{clean(item.get("name") or "(no name)")}"\n  TO     "{clean(new_name)}"')
    if passkeys(item):
        print("  NOTE   this entry holds a passkey. The edit is read back and the run stops if it differs, but the passkey itself "
              "could already be changed: keep the original in Apple Passwords or Chrome until you have checked this entry in Bitwarden")
    if ask(f"\nThis changes the entry's name and nothing else. Type {RENAME_WORD} to continue: ") != RENAME_WORD:
        sys.exit("Not confirmed. Nothing was changed.")
    apply([g])
    print("Done.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    steps = ap.add_subparsers(dest="stage", required=True, metavar="step")
    for stage, help_text in [("exact", "identical copies only"), ("merge", "every group safe to merge"),
                             ("pick", "choose between different passwords"), ("fixurls", "add https:// to logins saved with http:// only")]:
        p = steps.add_parser(stage, help=help_text)
        p.add_argument("--out-dir", required=True, help="folder for the plan file")
        p.add_argument("--apply", action="store_true", help="act on the plan after you type the confirmation word")
        p.add_argument("--limit", type=int, help="act on only the first N groups (a first run should use 1)")
    p = steps.add_parser("merge-entries", help=f"keep the first entry, fold the others into it and trash them, after you type {MERGE_WORD}")
    p.add_argument("keep", help="the entry to keep: its id (8 characters or more) or a search of names, usernames and addresses")
    p.add_argument("fold", nargs="+", help="an entry to fold in, named the same way")
    p = steps.add_parser("rename", help=f"give one entry a new name, after you type {RENAME_WORD}")
    p.add_argument("entry", help="the entry: its id (8 characters or more) or a search of names, usernames and addresses")
    p.add_argument("new_name", help="its new name")
    args = ap.parse_args()
    if args.stage == "merge-entries":
        run_merge(args.keep, args.fold)
        return
    if args.stage == "rename":
        run_rename(args.entry, args.new_name)
        return
    if args.limit is not None and args.limit < 1:
        sys.exit("--limit must be 1 or more")

    word = FIXURLS_WORD if args.stage == "fixurls" else CONFIRM_WORD
    if args.apply:
        print(f"Nothing in your vault changes until you have read the list below and typed {word}.\n", flush=True)
    else:
        print("PREVIEW ONLY: this step does not change, merge or delete anything in your vault.\n", flush=True)
    items = load_items()
    folders = load_folders()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.stage == "fixurls":
        run_fixurls(args, items, folders, out_dir)
        return
    acting, blocked, other_stage = select(find_groups(items), args.stage)
    plan = out_dir / f"plan-{args.stage}.md"
    plan.write_text(render_plan(args.stage, acting, blocked, other_stage, folders), encoding="utf-8")
    plan.chmod(0o600)
    print(f"{len(acting)} group(s) to change, {len(blocked)} left alone, {other_stage} for another stage. Plan: {plan}")
    print(f"\n{STAGE_SUMMARY[args.stage]}")
    if blocked:
        reasons = Counter(g.blocked for g in blocked)
        print("Left alone: " + ", ".join(f"{n} {why}" for why, n in reasons.most_common()) + ".")
        if set(PICK_REASONS) & set(reasons):
            print("Groups with different passwords or a masked username: dedupe pick shows each copy's addresses and dates "
                  "and lets you choose the password to keep, or keep both.")

    if not args.apply:
        sample = acting[:3]
        if sample:
            head = "all" if len(sample) == len(acting) else f"the first {len(sample)} of {len(acting)}"
            print(f"\nPreview: {head} groups (every group is in the plan file)\n")
            if args.stage == "pick":
                print("\n\n".join(render_choices(g, by_newest_password(g), n, len(acting), folders)
                                  for n, g in enumerate(sample, start=1)) + "\n")
            else:
                print(render_preview(sample, len(acting), folders))
        print("Nothing was changed. Add apply to act on this plan.")
        return
    todo = acting[: args.limit] if args.limit else acting
    if not todo:
        print("Nothing to do.")
        return
    if args.stage == "pick":
        todo = choose_passwords(todo, folders)
        if not todo:
            print("No group was chosen. Nothing was changed.")
            return
    edits = sum(1 for g in todo if g.merged is not None)
    trash = sum(len(g.others) for g in todo)
    print(f"\nActing on {len(todo)} of {len(acting)} groups:\n")
    print(render_preview(todo, len(todo), folders))
    answer = ask(
        f"This will edit {edits} kept {'copy' if edits == 1 else 'copies'} and move {trash} {'copy' if trash == 1 else 'copies'} "
        f"to the Bitwarden trash, where they stay for 30 days. Type {CONFIRM_WORD} to continue: ")
    if answer != CONFIRM_WORD:
        sys.exit("Not confirmed. Nothing was changed.")
    apply(todo)
    print(f"Done. {trash} {'copy is' if trash == 1 else 'copies are'} in the web vault's Trash for 30 days. Run again to see what is left.")


if __name__ == "__main__":
    main()
