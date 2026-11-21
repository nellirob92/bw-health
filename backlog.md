# Backlog

Work that was considered and left out, with the reason.

- **A `BW_HEALTH_USER` environment variable as a second way to name a profile.** Left out on purpose:
  a variable that lingers in a Terminal tab is how one person's run lands in another person's profile.
  `--user NAME` on the line is the only way.
- **A step that deletes a profile's folders** (sign-in data, import folder, dedupe plan, reports).
  `logout` signs out and points at leftover import files, but removing them is still done by hand in Finder.
- **A check of `logout` and `--logout-after` against the real Bitwarden command-line app.** The tests use
  a stand-in; the first real sign-out is the check.
- **A person's reports are not removed by `logout`.** They list site names and usernames (never
  passwords) and stay, newest 10, until they are trashed by hand. A report an earlier version left on
  the Desktop is pointed out on the next run, not removed.
- **Retire the old `main` paste line.** A line that still points at `main` keeps working: it runs the
  entry script on `main`, which fetches its files from its own version's tag and shows the tagged line.
  Making that line refuse, or removing the entry script from `main`, is not done.
- **Pin the entry script itself.** The checksums cover the files the script fetches, not `bw-health.sh`,
  which is trusted as GitHub serves it for the tag. A tag can be moved unless the repository protects
  `v*` tags; a ruleset that blocks deleting or moving them is planned, not applied.
- **Item-name tags for the fix order.** A folder named in `fix_order.txt` sets a login's tier; a tag in
  an item's own name does not.
- **Two-step matching across unrelated addresses of one site.** A login "supports two-step" when its
  address is on the 2FA Directory list, and "likely supports" it when the address is under a listed one,
  above one, or shares a domain named in `fix_order.txt`. A site whose sign-in address is none of those
  (a sibling of the listed address, with no domain in `fix_order.txt`) is not flagged.
- **A check that the links in the report open the right pages** (the web vault's item, account and
  two-step pages, and each site's change-password address). They are built, never fetched.

## Audit findings, release 1.0.0

The release audit looked for blockers only (a password printed, logged or written; a vault write outside
the dedupe step; a way round the checksums or the tag; one profile reaching another's data; a break of
the old `main` paste line) and found none. What it found besides, most serious first:

- **One shared copy of the fetched scripts.** Every run, of any version and any profile, copies its four
  files into the same folder (`~/Library/Application Support/bw-health`) before using them. Two checkouts
  or versions run close together can overwrite each other's scripts between the copy and the use.
  Proposal: copy into a folder of the run's own, named for the version and the files' checksums (or a
  temporary folder per run), and run the scripts from there.
- **A fixed temporary name while fetching.** Each file is written to `<name>.new` in that shared folder
  before its checksum is checked. Two runs at the same moment can install a file the other is still
  writing. Proposal: a unique temporary name per run (`mktemp`).
- **Progress is matched by item id, not by account.** If a profile, or the shared sign-in, is signed out
  and someone else signs in, the next report says everything was fixed and everything is new. Proposal:
  keep Bitwarden's account id in the progress file and start again when it differs.
- **A download of the two-step list that is cut off stops the whole report.** A failed connection reads
  "not checked this run", but a connection that drops mid-download raises an error the report does not
  catch. Proposal: treat `http.client.HTTPException` like the other download failures.
- **The first minutes after `main` moves to a new release.** GitHub can keep serving the previous entry
  script from `main` for about five minutes. A line that points at `main` and is served a script from
  before 1.0.0 fetches the new Python files without `fix_order.txt` and stops at the report, loudly.
  From 1.0.0 on, the script fetches from its own tag, so later releases do not have this gap.
- **Two installs that are still unpinned**, both from before this release: `uv` comes from its own
  installer script, and `uv run` takes the newest `zxcvbn` that satisfies `>=4.4`.
- **Addresses that are not web addresses.** An `androidapp://` address is treated as a site, so its
  "Site" and "Change password" links lead nowhere.
- **Notes on cards and identities are not checked** for passwords; only secure notes and logins are.
- **`logout` with a name that was never used lists the profile names on this Mac account.**
- **The report-pruning pattern for the shared folder would also match a profile's reports** if they
  were ever in the same folder. They never are: each profile has its own.
- **Not exercised by a test:** the fixed User-Agent of the two-step download, and the real Bitwarden
  app answering `list folders` while the script itself is on stdin (`list items` already works that way).
