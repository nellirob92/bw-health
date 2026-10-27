#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Diff Chrome or Apple password exports against a Bitwarden vault before importing.

Bitwarden's importer never de-duplicates, so this splits export rows into NEW (written to a
Bitwarden csv to import), SAME (skipped) and CONFLICT (same site and user, different
password; listed for a human). Read-only on the vault; safe to run twice.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

LOGIN_TYPE = 1
BW_CSV_HEADER = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt",
                 "login_uri", "login_username", "login_password", "login_totp"]
COLUMN_ALIASES = {
    "name": ("name", "title"),
    "url": ("url", "login_uri", "website", "uri"),
    "username": ("username", "login_username", "user"),
    "password": ("password", "login_password"),
    "notes": ("note", "notes"),
    "totp": ("otpauth", "login_totp", "totp"),
}


@dataclass(frozen=True)
class Row:
    source: str
    name: str
    url: str
    username: str
    password: str
    notes: str
    totp: str

    @property
    def key(self) -> tuple[str, str]:
        return host_of(self.url), self.username.strip().lower()


def host_of(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if url.startswith("android://"):
        return url.rsplit("@", 1)[-1].rstrip("/").lower()
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except ValueError:  # real exports hold malformed URLs (an unclosed IPv6 bracket); one must not stop the diff
        return url.lower()
    host = (parsed.hostname or url).lower()
    return host[4:] if host.startswith("www.") else host


def run_bw(*args: str) -> str:
    try:
        done = subprocess.run(["bw", *args], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        sys.exit("bw CLI not found. Install it: brew install bitwarden-cli")
    if done.returncode != 0:
        sys.exit(f"bw {' '.join(args)} failed:\n{done.stderr.strip() or done.stdout.strip()}")
    return done.stdout


def load_vault(path: str | None) -> list[dict]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    if not os.environ.get("BW_SESSION"):
        sys.exit('Vault is locked. Run:  export BW_SESSION="$(bw unlock --raw)"  then try again.')
    if json.loads(run_bw("status")).get("status") != "unlocked":
        sys.exit("Vault is not unlocked. Run: bw login, then export BW_SESSION=\"$(bw unlock --raw)\"")
    run_bw("sync")
    return json.loads(run_bw("list", "items"))


def vault_index(items: list[dict]) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """(host, username) -> [(password, item name)], live login items only. One item may have many URIs."""
    index: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for it in items:
        if it.get("type") != LOGIN_TYPE or it.get("deletedDate"):
            continue
        login = it.get("login") or {}
        user = (login.get("username") or "").strip().lower()
        pw = login.get("password") or ""
        hosts = {host_of((u or {}).get("uri") or "") for u in login.get("uris") or []} - {""}
        for host in hosts:
            index.setdefault((host, user), []).append((pw, it.get("name") or "(no name)"))
    return index


def read_export(path: Path) -> list[Row]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            sys.exit(f"{path}: empty file")
        lower = {f.lower().strip(): f for f in reader.fieldnames}
        col: dict[str, str | None] = {}
        for field, aliases in COLUMN_ALIASES.items():
            col[field] = next((lower[a] for a in aliases if a in lower), None)
        for required in ("url", "username", "password"):
            if col[required] is None:
                sys.exit(f"{path}: no {required} column. Headers seen: {reader.fieldnames}")

        def get(r: dict, field: str) -> str:
            c = col[field]
            return (r.get(c) or "").strip() if c else ""

        rows = []
        for r in reader:
            if not get(r, "password"):
                continue
            rows.append(Row(
                source=path.name,
                name=get(r, "name") or host_of(get(r, "url")) or "(no name)",
                url=get(r, "url"),
                username=get(r, "username"),
                password=get(r, "password"),
                notes=get(r, "notes"),
                totp=get(r, "totp"),
            ))
        return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exports", nargs="+", help="CSV export files from Chrome, Apple Passwords, etc.")
    ap.add_argument("--out-dir", required=True, help="folder for new-for-bitwarden.csv and conflicts.md")
    ap.add_argument("--vault", help="JSON array from `bw list items` instead of calling bw (testing)")
    args = ap.parse_args()

    index = vault_index(load_vault(args.vault))
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Exports are read in the order given (newest first). The first password seen for a
    # site + username wins; a later export disagreeing is an export conflict, not a new row.
    new: dict[tuple[str, str], Row] = {}
    same: list[Row] = []
    conflicts: list[tuple[Row, list[str]]] = []
    export_conflicts: list[tuple[Row, Row]] = []
    for path in args.exports:
        for row in read_export(Path(path)):
            vault_matches = index.get(row.key, [])
            if vault_matches:
                if any(pw == row.password for pw, _ in vault_matches):
                    same.append(row)
                else:
                    conflicts.append((row, [name for _, name in vault_matches]))
            elif row.key not in new:
                new[row.key] = row
            elif new[row.key].password != row.password:
                export_conflicts.append((new[row.key], row))

    new_csv = out_dir / "new-for-bitwarden.csv"
    with new_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(BW_CSV_HEADER)
        for row in new.values():
            w.writerow(["", "", "login", row.name, row.notes, "", "0",
                        row.url, row.username, row.password, row.totp])
    os.chmod(new_csv, 0o600)

    lines = ["# Import diff", "",
             f"- New, written to `{new_csv}`: **{len(new)}**",
             f"- Already in the vault, identical, skipped: {len(same)}",
             f"- **Conflicts, decide by hand: {len(conflicts) + len(export_conflicts)}**", ""]
    if export_conflicts:
        lines += ["## Conflicts between exports", "",
                  "Two export files disagree on a password. The newer file's version was imported; "
                  "check the site still accepts it.", "",
                  "| Site | Username | Imported from | Disagrees |", "| --- | --- | --- | --- |"]
        for kept, other in sorted(export_conflicts, key=lambda c: c[0].key):
            lines.append(f"| {kept.key[0]} | {kept.username} | {kept.source} | {other.source} |")
        lines.append("")
    if conflicts:
        lines += ["## Conflicts", "",
                  "Same site and username, different password. Log in to the site to learn which one works, "
                  "then fix the Bitwarden item by hand. Neither password is shown here.", "",
                  "| Site | Username | From export | Bitwarden item |", "| --- | --- | --- | --- |"]
        for row, names in sorted(conflicts, key=lambda c: c[0].key):
            lines.append(f"| {row.key[0]} | {row.username} | {row.source} | {', '.join(names)} |")
        lines.append("")
    if new:
        lines += ["## New", "", "| Site | Username | From export |", "| --- | --- | --- |"]
        lines += [f"| {r.key[0]} | {r.username} | {r.source} |" for r in sorted(new.values(), key=lambda r: r.key)]
        lines.append("")
    lines.append("_Delete this folder after importing: the csv holds plain-text passwords._")
    (out_dir / "conflicts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:5]))
    print(f"\nDetails: {out_dir / 'conflicts.md'}")


if __name__ == "__main__":
    main()
