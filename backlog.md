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
  two-step pages, and each site's change-password address). They are built, never fetched, and have not
  been tried on a real vault.
- **The import diff still matches by host.** The report and the dedupe step group by site (registrable
  domain, from the pinned public suffix list); `bw_import_diff.py` still compares an export row with the
  vault by host and username, so `secure01.bank.com` in Chrome and `www.bank.com` in the vault are listed
  as new. Moving it to the same site key changes what gets imported, so it needs its own release.
- **Done ticks after quitting Safari.** The ticks live in the browser's storage for the report's
  `file://` page. Tried on macOS 27.2: Chrome 157 keeps them after quitting, and every report file shares
  them; Safari 27.2 keeps them between tabs and shares them across report files, but keeping them after
  quitting Safari has not been tried.
- **Whether iPhone AutoFill then offers a login** that the AutoFill fix gave an `https://` address. The
  fix is read back from Bitwarden; what the phone does with it has not been checked.
- **Refreshing the public suffix list.** `public_suffix_list.dat` is a pinned copy and goes stale slowly
  (new shared endings). It is updated by hand, with a new checksum and `VERSION`; nothing reminds anyone.
- **Copies of 1.0.0's files left in the shared bw-health folder.** 1.0.0 fetched its scripts into the
  shared application folder; 1.1.0 fetches into a per-run folder and neither uses nor removes those old
  copies. They hold no vault data. Removing them is left to a later release or by hand.
- **Username capitals.** A site's key lowercases the username, so `Member` and `member` are one account.
  A site where capitals make two accounts would be grouped as one; none is known.
- **A masked username that fits two accounts** stays its own row; the report cannot say which account it
  belongs to, and nothing offers to fill in the real username.
- **The shareable summary is replaced on every run**, never kept per date. A family member who wants the
  last one keeps their own copy.

## Audit findings, release 1.0.0

The release audit looked for blockers only (a password printed, logged or written; a vault write outside
the dedupe step; a way round the checksums or the tag; one profile reaching another's data; a break of
the old `main` paste line) and found none. What it found besides, most serious first:

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
- **Notes on cards and identities are not checked** for passwords; only secure notes and logins are.
- **`logout` with a name that was never used lists the profile names on this Mac account.**
- **The report-pruning pattern for the shared folder would also match a profile's reports** if they
  were ever in the same folder. They never are: each profile has its own.
- **Not exercised by a test:** the fixed User-Agent of the two-step download, and the real Bitwarden
  app answering `list folders` while the script itself is on stdin (`list items` already works that way).
