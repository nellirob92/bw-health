#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Trash or merge duplicate logins in a Bitwarden vault, one stage at a time.

A duplicate group is the same site and username (case-insensitive), the grouping the health
report uses. Three stages, each run on its own:

  exact  groups whose copies are identical in every field: keep one, trash the rest.
  merge  groups with the same password (or a missing one) but other details that differ: add the
         extra URLs, notes, custom fields and one-time-code seed to the kept
         copy, fill a missing password from another copy, then trash the rest.
  pick   groups whose only conflict is different passwords: the person picks, group by group, the
         password that works (copies listed newest password first, Enter skips), then it is merged
         like the merge stage and the other copies, with their passwords, go to the trash.

A copy that holds a passkey is always the kept copy, since a passkey cannot be moved. After every
edit the kept copy is read back, and the run stops before trashing anything if bw saved something
other than what was sent. A group is left alone, and listed with the reason, when copies have
different one-time-code seeds, a custom field with two values, an attachment, several passkeys or
one listed without its key, password history the kept copy lacks (bw edit cannot save a joined
history), or belong to an organization. Without --apply this only writes a plan. Trashed copies
stay in the web vault's Trash for 30 days; this script never deletes permanently.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from urllib.parse import urlparse

LOGIN_TYPE = 1
CONFIRM_WORD = "DEDUPE"
NOTE_SEPARATOR = "\n\n--- merged from a duplicate entry ---\n\n"
DIFFERENT_PASSWORDS = "different passwords"


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
    if items and not any("organizationId" in i for i in items):
        sys.exit("bw did not say which items belong to an organization, so shared items cannot be told apart. Nothing was changed.")
    return items


def load_folders() -> dict[str, str]:
    return {f["id"]: f.get("name") or "" for f in json.loads(run_bw("list", "folders")) if f.get("id")}


def host_of(item: dict) -> str:
    for u in (item.get("login") or {}).get("uris") or []:
        uri = (u or {}).get("uri") or ""
        if not uri:
            continue
        try:
            parsed = urlparse(uri if "://" in uri else f"https://{uri}")
        except ValueError:  # real vaults hold malformed URLs (an unclosed IPv6 bracket); one must not stop the run
            return uri.strip().lower()
        host = parsed.hostname or uri
        return host[4:] if host.startswith("www.") else host
    return ""


def login_of(item: dict) -> dict:
    return item.get("login") or {}


def account_key(item: dict) -> str | None:
    username = login_of(item).get("username") or ""
    host = host_of(item)
    return f"{host}|{username.lower()}" if host and username else None


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


def blocker(items: list[dict]) -> str | None:
    """Why this group must be left alone, or None when it is safe to act on."""
    if any(i.get("organizationId") for i in items):
        return "shared with an organization"
    if any(i.get("attachments") for i in items):
        return "has an attachment"
    if sum(1 for i in items if passkeys(i)) > 1:
        return "several copies hold a passkey"
    if any(not c.get("keyValue") or not c.get("credentialId") or not c.get("rpId") for i in items for c in passkeys(i)):
        return "a passkey that bw listed without its key"  # an edit would save the gap, and a read-back of a gap proves nothing
    if len({login_of(i).get("totp") for i in items if login_of(i).get("totp")}) > 1:
        return "different one-time-code seeds"
    seen: dict[tuple, str] = {}
    for i in items:
        for f in i.get("fields") or []:
            if seen.setdefault((f.get("name"), f.get("type")), f.get("value")) != f.get("value"):
                return "a custom field with different values"
    # bw edit keeps the item's own password history and discards the history it is sent, so a copy's history cannot be carried over
    keeper = pick_keeper(items)
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
    if len({pw for i in items if (pw := login_of(i).get("password"))}) > 1:  # an empty password is a gap, not a conflict
        return DIFFERENT_PASSWORDS  # checked last, so this reason means the pick stage can handle the group
    return None


def pick_keeper(items: list[dict]) -> dict:
    holders = [i for i in items if passkeys(i)]  # a passkey cannot be moved to another item, so its holder is kept
    if holders:
        return holders[0]
    return max(items, key=lambda i: (bool(login_of(i).get("totp")), i.get("revisionDate") or "", i["id"]))


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
    by_account: dict[str, list[dict]] = {}
    for i in items:
        if i.get("type") == LOGIN_TYPE and not i.get("deletedDate") and account_key(i):
            by_account.setdefault(account_key(i), []).append(i)
    groups = []
    for account, members in sorted(by_account.items()):
        if len(members) < 2:
            continue
        keeper = pick_keeper(members)
        others = [m for m in members if m["id"] != keeper["id"]]
        g = Group(account, keeper, others, blocked=blocker(members))
        g.exact = len({fingerprint(m) for m in members}) == 1
        if not g.blocked and not g.exact:
            merged = merge_into(keeper, others)
            g.merged = merged if merged != keeper else None
        groups.append(g)
    return groups


def select(groups: list[Group], stage: str) -> tuple[list[Group], list[Group], int]:
    """(groups this stage acts on, groups left alone, groups waiting for another stage)."""
    if stage == "pick":
        acting = [g for g in groups if g.blocked == DIFFERENT_PASSWORDS]
        blocked = [g for g in groups if g.blocked and g.blocked != DIFFERENT_PASSWORDS]
    else:
        acting = [g for g in groups if not g.blocked and g.exact == (stage == "exact")]
        blocked = [g for g in groups if g.blocked]
    other_stage = len(groups) - len(acting) - len(blocked)
    return acting, blocked, other_stage


def when(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def item_dates(item: dict) -> list[tuple[str, datetime | None]]:
    return [("password changed", when(login_of(item).get("passwordRevisionDate"))),
            ("edited", when(item.get("revisionDate"))), ("created", when(item.get("creationDate")))]


def by_newest_password(g: Group) -> list[dict]:
    """The group's copies, newest password first: when bw saw the password change, then the last edit, then creation."""
    oldest = datetime.min.replace(tzinfo=timezone.utc)
    return sorted([g.keeper, *g.others], key=lambda i: ([d or oldest for _, d in item_dates(i)], i["id"]), reverse=True)


def set_password(g: Group, password: str) -> None:
    """The keeper with the chosen password and everything the merge stage would add."""
    merged = merge_into(g.keeper, g.others)
    merged["login"]["password"] = password
    g.merged = merged if merged != g.keeper else None


STAGE_SUMMARY = {
    "exact": ("Exact stage: a login saved more than once (same site and username) where the copies are identical in every field. "
              "One copy is kept and the rest go to the Bitwarden trash."),
    "merge": ("Merge stage: a login saved more than once (same site and username) with the same password, or a missing one, "
              "but other details that differ. The kept copy gains the other copies' URLs, "
              "notes, custom fields, one-time-code seed, a missing password and any favorite or re-prompt setting, then the rest go to the "
              "Bitwarden trash. A copy with a passkey is always the one kept. Only the kept copy's name and folder survive."),
    "pick": ("Pick stage: a login saved more than once (same site and username) whose copies have different passwords and "
             "no other conflict. Each copy is listed newest password first, with its dates. Type the number of the password "
             "that works, or press Enter to skip the group. The kept entry takes that password and gains the other copies' "
             "details as in the merge stage. The other copies, with their passwords, go to the Bitwarden trash for 30 days. "
             "A copy with a passkey is always the one kept."),
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
        if passkeys(g.keeper):
            lines.append("  NOTE   the kept copy holds a passkey. The edit is read back and the run stops before trashing if it differs, "
                         "but the passkey itself could already be changed: keep the original in Apple Passwords or Chrome until you have checked this entry in Bitwarden")
        lines.append("")
    return "\n".join(lines)


def render_choices(g: Group, copies: list[dict], n: int, total: int, folders: dict[str, str]) -> str:
    """A pick group's copies, numbered newest password first, with their dates in local time and the kept entry marked."""
    lines = [f"[{n}/{total}] {g.label}, {len(copies)} copies with different passwords"]
    for k, item in enumerate(copies, start=1):
        dates = ", ".join(f"{label} {d.astimezone():%Y-%m-%d %H:%M}" for label, d in item_dates(item) if d)
        mark = "" if item is not g.keeper else "  (kept entry, holds a passkey)" if passkeys(item) else "  (kept entry)"
        lines.append(f'  {k}  "{clean(item.get("name") or "(no name)")}"  folder: {folder_name(item, folders)}  {dates}{mark}')
    return "\n".join(lines)


def choose_passwords(groups: list[Group], folders: dict[str, str]) -> list[Group]:
    """Asks, group by group, which copy's password works. Enter, or anything but a listed number, skips the group."""
    chosen = []
    for n, g in enumerate(groups, start=1):
        copies = by_newest_password(g)
        print(render_choices(g, copies, n, len(groups), folders))
        answer = ask("Type the number of the password that works (1 is the newest), or press Enter to skip: ")
        if not answer:
            print("Skipped.\n")
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
             f"- Groups for the other stage: **{other_stage}**", ""]
    lines += ["## Will change", ""]
    if acting:
        lines += ["| Account | Copies | Kept | Trashed | What the kept copy gains |", "| --- | --- | --- | --- | --- |"]
        lines += [f"| {g.label} | {len(g.others) + 1} "
                  f"| {clean(g.keeper.get('name') or '(no name)')} ({folder_name(g.keeper, folders)}) "
                  f"| {'; '.join(clean(o.get('name') or '(no name)') + ' (' + folder_name(o, folders) + ')' for o in g.others)} "
                  f"| {'the password you choose; ' if stage == 'pick' else ''}{describe_change(g)} |"
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


@cache
def terminal():
    """Opened once, so successive answers are successive lines (stdin is not the keyboard under curl | bash)."""
    return open(os.environ.get("BW_HEALTH_TTY", "/dev/tty"), encoding="utf-8")


def ask(prompt: str) -> str:
    print(prompt, end="", flush=True)
    return terminal().readline().strip()


def verify_edit(g: Group) -> None:
    """Read the kept copy back after the edit. Stops the run, before anything is trashed, if bw saved something other
    than what was sent: a passkey cannot be recreated, and the real edit path has been seen to rebuild the login."""
    got = json.loads(run_bw("get", "item", g.keeper["id"]))
    want = g.merged or g.keeper
    wrong = []
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


def apply(groups: list[Group]) -> None:
    for g in groups:  # checked up front so a refusal changes nothing
        if any(str(i["id"]).startswith("-") for i in [g.keeper, *g.others]):
            sys.exit(f"Refusing {g.label}: an item id starts with '-', which bw could read as an option. Nothing was changed.")
    for n, g in enumerate(groups, start=1):
        if g.merged is not None:
            encoded = base64.b64encode(json.dumps(g.merged).encode("utf-8")).decode("ascii")
            run_bw("edit", "item", g.keeper["id"], stdin=encoded)
            verify_edit(g)
        for other in g.others:
            run_bw("delete", "item", other["id"])
        print(f"[{n}/{len(groups)}] {g.label}: kept one, trashed {len(g.others)}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("stage", choices=["exact", "merge", "pick"],
                    help="exact: identical copies only; merge: same password, details differ; pick: choose between different passwords")
    ap.add_argument("--out-dir", required=True, help="folder for the plan file")
    ap.add_argument("--apply", action="store_true", help="act on the plan after you type the confirmation word")
    ap.add_argument("--limit", type=int, help="act on only the first N groups (a first run should use 1)")
    args = ap.parse_args()
    if args.limit is not None and args.limit < 1:
        sys.exit("--limit must be 1 or more")

    if args.apply:
        print("Nothing in your vault changes until you have read the list below and typed DEDUPE.\n", flush=True)
    else:
        print("PREVIEW ONLY: this step does not change, merge or delete anything in your vault.\n", flush=True)
    acting, blocked, other_stage = select(find_groups(load_items()), args.stage)
    folders = load_folders()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = out_dir / f"plan-{args.stage}.md"
    plan.write_text(render_plan(args.stage, acting, blocked, other_stage, folders), encoding="utf-8")
    plan.chmod(0o600)
    print(f"{len(acting)} group(s) to change, {len(blocked)} left alone, {other_stage} for the other stage. Plan: {plan}")
    print(f"\n{STAGE_SUMMARY[args.stage]}")
    if blocked:
        reasons = Counter(g.blocked for g in blocked)
        print("Left alone: " + ", ".join(f"{n} {why}" for why, n in reasons.most_common()) + ".")
        if DIFFERENT_PASSWORDS in reasons:
            print(f"Groups with {DIFFERENT_PASSWORDS}: dedupe pick shows each copy's dates and lets you choose the password to keep.")

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
