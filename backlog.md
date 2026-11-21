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
- **Progress after a profile is signed in to a different account.** The progress file is compared by
  item id. Signing a profile out and in again as someone else would count every earlier item as fixed.
- **A check that the links in the report open the right pages** (the web vault's item, account and
  two-step pages, and each site's change-password address). They are built, never fetched.
