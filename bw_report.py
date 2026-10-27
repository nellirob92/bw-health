#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["zxcvbn>=4.4"]
# ///
"""Password health report for a Bitwarden vault: exposed, reused, weak and duplicate logins.

Reads the vault with `bw list items` (read-only) and never prints a password. The breach
check sends only the first 5 characters of each password's SHA-1 to Have I Been Pwned.
Needs BW_SESSION from `bw unlock --raw`, or `--input items.json` for a saved export.
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
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

from zxcvbn import zxcvbn

LOGIN_TYPE = 1
WEAK_MAX_SCORE = 2  # zxcvbn: 0-2 weak, 3 ok, 4 strong
ZXCVBN_MAX_LENGTH = 72  # zxcvbn raises on longer input; a longer password is scored on its first 72 characters
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

# Keyword -> tier. Lower tier = fix first. Matched against the item name and its site host.
PRIORITY = {
    1: ("gmail", "google", "icloud", "apple", "outlook", "hotmail", "yahoo", "proton", "mail"),
    2: ("bank", "chase", "wells", "citi", "capital", "amex", "paypal", "venmo", "zelle",
        "fidelity", "schwab", "vanguard", "robinhood", "coinbase", "irs", "ssa.gov"),
    3: ("roblox", "steam", "xbox", "playstation", "nintendo", "epic", "discord",
        "instagram", "tiktok", "snapchat", "facebook", "x.com", "twitter"),
}


@dataclass
class Login:
    item_id: str
    name: str
    username: str
    host: str
    password: str
    in_trash: bool

    @property
    def label(self) -> str:
        who = f" ({self.username})" if self.username else ""
        where = f" - {self.host}" if self.host and self.host not in self.name else ""
        return f"{self.name}{who}{where}"

    @property
    def account(self) -> str:
        """Same site + username (case-insensitive) is one account; a login missing either stands alone."""
        if self.host and self.username:
            return f"{self.host}|{self.username.lower()}"
        return f"item:{self.item_id}"

    @property
    def tier(self) -> int:
        hay = f"{self.name} {self.host}".lower()
        for tier, words in PRIORITY.items():
            if any(re.search(rf"\b{re.escape(w)}\b", hay) for w in words):
                return tier
        return 4


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


def load_items(path: str | None) -> list[dict]:
    if path:
        raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
        return json.loads(raw)
    if not os.environ.get("BW_SESSION"):
        sys.exit('Vault is locked. Run:  export BW_SESSION="$(bw unlock --raw)"  then try again.')
    status = json.loads(run_bw("status"))
    if status.get("status") != "unlocked":
        sys.exit(f"bw status is '{status.get('status')}'. Run: bw login, then export BW_SESSION=\"$(bw unlock --raw)\"")
    run_bw("sync")
    return json.loads(run_bw("list", "items"))


def host_of(item: dict) -> str:
    for u in (item.get("login") or {}).get("uris") or []:
        uri = (u or {}).get("uri") or ""
        if not uri:
            continue
        try:
            parsed = urlparse(uri if "://" in uri else f"https://{uri}")
        except ValueError:  # real vaults hold malformed URLs (an unclosed IPv6 bracket); one must not stop the report
            return uri.strip().lower()
        host = parsed.hostname or uri
        return host[4:] if host.startswith("www.") else host
    return ""


def to_logins(items: list[dict]) -> tuple[list[Login], int]:
    logins, no_password = [], 0
    for it in items:
        if it.get("type") != LOGIN_TYPE:
            continue
        login = it.get("login") or {}
        pw = login.get("password") or ""
        if not pw:
            no_password += 1
            continue
        logins.append(Login(
            item_id=it["id"],
            name=it.get("name") or "(no name)",
            username=login.get("username") or "",
            host=host_of(it),
            password=pw,
            in_trash=bool(it.get("deletedDate")),
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
            headers={"User-Agent": "bw_report family vault check", "Add-Padding": "true"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            suffix, _, count = line.strip().partition(":")
            full_hash = prefix + suffix
            if full_hash in full and int(count) > 0:
                found[full_hash] = int(count)
    return found


def build(items: list[dict], check_hibp: bool) -> Report:
    rep = Report()
    logins, rep.no_password = to_logins(items)
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
    return rep


def md_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    out += ["| " + " | ".join(c.replace("|", "/") for c in r) + " |" for r in rows]
    return "\n".join(out)


def render(rep: Report) -> str:
    tier_name = {1: "1 - email / Apple / Google", 2: "2 - money", 3: "3 - gaming / social", 4: "4 - everything else"}
    exposed_ids = {l.account for l, _ in rep.exposed}
    reused_ids = {l.account for ls in rep.reused.values() for l in ls}
    weak_ids = {l.account for l, _, _ in rep.weak}
    at_risk: dict[str, Login] = {}
    for l in [l for ls in rep.reused.values() for l in ls] + [l for l, _, _ in rep.weak] + [l for l, _ in rep.exposed]:
        at_risk.setdefault(l.account, l)

    lines = ["# Bitwarden password health report", ""]
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
         ["**Logins that need a new password**", f"**{len(at_risk)}**"]],
    ))
    lines.append("")

    lines += ["## Fix in this order", ""]
    if not at_risk:
        lines.append("Nothing. Every live password is unique, strong and unseen in a breach.")
    else:
        rows = []
        for l in sorted(at_risk.values(), key=lambda x: (x.tier, 0 if x.account in exposed_ids else 1, x.name.lower())):
            why = ", ".join(w for w, hit in (("exposed", l.account in exposed_ids),
                                             ("reused", l.account in reused_ids),
                                             ("weak", l.account in weak_ids)) if hit)
            rows.append([tier_name[l.tier], l.label, why])
        lines.append(md_table(["Priority", "Login", "Why"], rows))
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
            lines.append(f"- {host} ({user}): {len(ls)} copies")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("_Passwords themselves are never shown in this report. Breach check: Have I Been Pwned range API (k-anonymity)._")
    return "\n".join(lines)


HTML_HEAD = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitwarden password health report</title><style>
body{font:16px/1.5 -apple-system,Helvetica,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.6rem}h2{font-size:1.2rem;margin-top:2rem;border-bottom:2px solid #ddd;padding-bottom:.25rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f3f3f3}tr:nth-child(even) td{background:#fafafa}li{margin:.15rem 0}
</style></head><body>
"""


def inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"<em>\1</em>", text)


def to_html(md: str) -> str:
    """The subset of Markdown this report emits: headings, pipe tables, bullets, bold, italics."""
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
    ap.add_argument("--out", help="write the report here instead of stdout")
    ap.add_argument("--html", action="store_true", help="emit HTML instead of Markdown")
    ap.add_argument("--no-hibp", action="store_true", help="skip the Have I Been Pwned breach check")
    args = ap.parse_args()

    items = load_items(args.input)
    report = render(build(items, check_hibp=not args.no_hibp))
    if args.html:
        report = to_html(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"wrote {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    main()
