# bw-health

A one-line password check-up for a Bitwarden vault, for family members on a Mac. It finds passwords that
are exposed in a breach, reused, weak or saved twice and shows them on one page, with a summary you can share.
It helps you move old Chrome and Apple passwords in, and can tidy duplicate entries and AutoFill addresses.
It works on the free Bitwarden plan.

- [Run the check-up](#run-the-check-up)
- [Move your old passwords in](#move-your-old-passwords-in)
- [Several people on one Mac](#several-people-on-one-mac)
- [Share a summary](#share-a-summary)
- [Clean up duplicates](#clean-up-duplicates)
- [Fix AutoFill addresses](#fix-autofill-addresses)
- [If something goes wrong](#if-something-goes-wrong)
- [Privacy and safety](#privacy-and-safety)
- [For maintainers](#for-maintainers)

## Run the check-up

Open Terminal (press Command-Space, type `Terminal`, press Return), paste this line, press Return:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.1.1/bw-health.sh | bash
```

It asks for your Bitwarden email (the first time only), your master password, and the two-step code if
Bitwarden asks for one. Nothing shows on the screen while you type the password. It then opens the report
in your browser.

The report is one page. At the top: how many sites need work, a ring and bars that count them by problem and
by kind of site, and **Fix these first**, the ten most urgent. Below are the tables. Each problem is a chip with
its word (Exposed, Reused, Weak, ...), so nothing is told by color alone, and the page follows the Mac's dark
mode, fits a phone and prints.

- **One row per site.** A site is a website and a username: `secure01.bank.com`, `www.bank.com` and the
  bank's other addresses count as one site, and a "Copies" column says how many entries it has. Shared
  endings such as `co.uk` or `github.io` are told apart with the public list of them, so two people's
  `github.io` sites stay two.
- **Links on the values.** Click a site to go to its change-password address (if you land on the home page,
  look under account settings). Click the account to open the entry in Bitwarden. A site, a device on your
  home network or an app saved with no `https://` address gets no link.
- **Sort, filter, hide done.** Click a column to sort, type to filter, tick a row when it is done and hide
  the done ones. The ticks are remembered in this browser only (Safari and Chrome both keep them for a report
  opened from the Mac). Without JavaScript the page is plain tables.
- **Masked usernames.** An export can save a username with `*` in place of some letters. If what is left
  fits exactly one other username on the same site (same length, same letters where shown), that entry is
  listed on the account's row as a "masked copy", and the duplicate cleanup sends it to `dedupe pick`, never
  to an automatic merge. Otherwise it is a row of its own with a "Masked" chip: type the real username in
  Bitwarden.

**This check only reads your vault.** It never merges, deletes or changes anything, and no password is
ever shown. It locks your vault again when it finishes.

| The report lists | Meaning |
| --- | --- |
| Fixed since last time | From the second run on, counted in sites: how many were fixed, how many are left, and how many are new (marked NEW). The counts of Bitwarden entries are in the small totals line. |
| Fix in this order | Most serious first: an exposed password, then a reused or weak one, then the smaller fixes (two-step, AutoFill, duplicates, masked, old). Within each, by kind of site: email, identity (.gov, login.gov, id.me) and Apple, Google and Microsoft accounts first, then money, then phone, utilities, insurance and health, then gaming and social, then everything else. One row per site, with its problems and its number of copies. |
| Exposed in a breach | The password appears in public breach lists. Only the first 5 characters of its SHA-1 hash leave your Mac (Have I Been Pwned's range check). |
| Reused | The same password is used on more than one account. |
| Weak | The password is short or predictable. |
| Duplicate entries | The same site and username is saved more than once. "Safe to merge" says Yes, "Needs pick" (different passwords, or a masked copy) or No with the reason, and the section gives the exact line to paste. |
| Two-step login | The site offers two-step login and no code is saved in the entry. Check that it is turned on at the site: the entry cannot show that. "Supports" means the saved address is on the public list; "likely supports" means only a related address is. If the list cannot be downloaded, the section says "not checked this run". |
| AutoFill problems | The entry has no web address, only an `http://` one, or an address that isn't a web address (such as `.something`, with no real domain), so AutoFill may not offer it on the secure page. The last kind is never offered to the AutoFill fix: correct it by hand. A device at home (a router) is not flagged. The section says how many the [AutoFill fix](#fix-autofill-addresses) can do. |
| Unchanged for 3+ years | The password has not changed in three years. Importing resets these dates, so right after an import the section reads "Checked on later runs". |
| Notes that may hold a password | A note with a line like `password: ...`. Only the item's name is shown, never the note. |
| Your Bitwarden account | Links to check that your Bitwarden email is verified and two-step login is on. The check-up cannot see either. |

A section with nothing in it is a single line that says "Nothing found".

**Where the report is kept.** Each run saves a dated report in
`~/Library/Application Support/bw-health/Reports` and opens it from there. It is never put on the Desktop,
in Documents or in iCloud. The newest 10 are kept; older ones are removed, and the run says how many.

**Paste line from before version 1.0.0?** It still works and now shows the line above, which always runs
exactly the version it names.

## Move your old passwords in

1. Export from the old place. Chrome: go to passwords.google.com, click the gear, then Export passwords.
   Apple: open the Passwords app on the Mac, File menu, Export All Passwords.
2. Paste the same line again within 7 days. It moves the file out of Downloads into a "Bitwarden Import"
   folder inside `~/Library/Application Support/bw-health`. That folder is never on the Desktop and never
   synced to iCloud.
3. It compares the export with your vault and writes two files there: `new-for-bitwarden.csv` (only the
   logins your vault does not have yet) and `conflicts.md` (same site and username, different password).
4. You import the csv yourself: at vault.bitwarden.com choose Tools, then Import data, format
   "Bitwarden (csv)".
5. When you are done, drag the whole folder to the Trash and empty it. The files inside hold your
   passwords in plain text.

An Apple csv export never includes passkeys. The run says so and tells you how to move them with the
iPhone's transfer.

## Several people on one Mac

To check several people's vaults from one Mac account, one after another, give each person a name with
`--user`. Add the words after `bash -s --` on the paste line:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.1.1/bw-health.sh | bash -s -- --user mom
```

| Add this | What happens |
| --- | --- |
| `--user mom` | The check-up for mom, with her own Bitwarden sign-in, import folder, dedupe plan and reports. The name is lowercase letters, digits and hyphens. |
| `--user mom dedupe merge` | Any other step, for mom. |
| `--user mom logout` | Signs mom out of Bitwarden on this Mac. |
| `--user mom --logout-after` | Signs mom out when the run ends. |

- Every run with a name says which Bitwarden account that name is signed in as. Check it before going on.
- Exports are never picked up on their own. The run lists the password export files in Downloads and asks
  which ones are that person's. Only those are moved, into that person's folder under
  `~/Library/Application Support/bw-health/profiles`. The rest stay in Downloads, so trash them when their
  owner's run is done.
- The Passwords app on the Mac holds the passwords of the Mac's own Apple Account. For someone else,
  export on their own Mac and AirDrop the file over.
- Each person's reports and progress are kept in their own folder under `profiles`, apart from everyone else's.
- Without `--user`, nothing changes: one shared sign-in and the shared folders.

## Share a summary

Each check-up also writes **Bitwarden Summary.html** (or **Bitwarden Summary - mom.html** with `--user mom`)
next to the reports, and says where. It holds counts only: how many sites need work, three plain steps in
fix-first order (email and main accounts, then money, then the rest, with two-step login turned on where it
is offered), the counts by problem and by kind of site (a count of 0 is left out), and what an attacker or an
AI tool could do with each kind of problem. It has no site, username, web address, Bitwarden id, link or
password, so it can be sent to family. Each run replaces it, and only once the report itself is written. The
summary and the report show the same check-up time, so a pair from one run can be told from two.

To write and open only the summary, with no report and no import step:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.1.1/bw-health.sh | bash -s -- --summary-only
```

## Clean up duplicates

Importing from both Chrome and Apple usually leaves two copies of the same login. Cleaning them up is a
**separate step that you start yourself**, and by default it is a **preview that changes nothing**. It only
changes your vault when you add `apply` and then type `DEDUPE` after reading the full list.

Add the words after `bash -s --` on the paste line, for example:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.1.1/bw-health.sh | bash -s -- dedupe merge
```

| Add this | What happens |
| --- | --- |
| `dedupe exact` | Preview: copies that are identical in every field. |
| `dedupe merge` | Preview: copies with the same password (or a missing one), the identical ones included. This is the step the report's "Safe to merge: Yes" means. |
| `dedupe pick` | Preview: copies whose only conflict is different passwords, or a masked username, each listed newest password first with its addresses and dates. |
| `dedupe exact apply` or `dedupe merge apply` | Acts on the preview, after you read the list and type `DEDUPE`. |
| `dedupe pick apply` | Asks, group by group, which password works (type its number; Enter keeps both copies as they are), then acts after `DEDUPE`. |
| `... apply 10` | Acts on only the first 10 groups. Start with `apply 1`. |

**Same site.** Copies are of one login when they have the same username and the same site, read the way the
report reads it: `secure01.bank.com` and `www.bank.com` are one site, `a.github.io` and `b.github.io` are two.

**What it does to a group of copies.** One copy is kept: the one holding a passkey, otherwise the one edited
most recently. It gains the other copies' URLs (the same site
written differently counts once), notes, custom fields, one-time-code seed, a missing password, and a
favorite or master password re-prompt setting that any copy has turned on. The other
copies go to Bitwarden's Trash, where they stay for 30 days and can be restored. Nothing is ever deleted
permanently. Only the kept copy's name and folder survive.

**Passkeys.** A copy that holds a passkey is always the one kept, because a passkey cannot be moved. After
every edit the kept copy is read back from Bitwarden, and the run stops before trashing anything if what
was saved differs from what was sent. The read-back can detect a damaged passkey but cannot undo it, so keep
the original in Apple Passwords or Chrome until you have checked that entry in Bitwarden.

**Different passwords or a masked username (`dedupe pick`).** Each copy is shown with its addresses. When
the copies were saved for different addresses, or one has a masked username, the list says they may be
separate accounts: press Enter to keep both. Copies are ranked by when their password was set: its last change,
or the copy's creation if Bitwarden never saw it change (an import), with the last edit breaking ties. Dates
are shown in your local time. The kept entry takes the password you pick and
gains the other copies' details as above. The other copies, with their passwords, go to the Trash, so sign in
with the picked password before their 30 days are up.

**Left alone, and listed with the reason:** copies with different one-time-code seeds, a custom field with
two values, an attachment, several passkeys (or one Bitwarden listed without its
key), password history the kept copy lacks (Bitwarden's command line cannot save a joined history), the same
URL with two different match settings, and anything shared with an organization.

A plan listing every group (names and counts, never a password) is written to
`~/Library/Application Support/bw-health/Dedupe Plan`.

## Fix AutoFill addresses

A login saved with only an `http://` address may not be offered by AutoFill on the site's secure page. This
step adds the `https://` version of each such address, with the same match setting, and keeps the old one.
Nothing else in the entry changes and nothing goes to the Trash. Like the duplicate cleanup it is a preview
until you add `apply` and type `FIXURLS`:

| Add this | What happens |
| --- | --- |
| `fixurls` | Preview: the logins it would change, and the ones it leaves alone with the reason. |
| `fixurls apply 1` | Changes the first login after you type `FIXURLS`. Without a number, all of them. |

Left alone: a login that holds a passkey (the edit rewrites the whole login, so add its `https://` address
by hand in Bitwarden), one shared with an organization, one whose address cannot be read, and devices on
your home network (a router or printer has no `https://` page). After each edit the entry is read back, and
the run stops if the `https://` address did not come back. Whether AutoFill then offers it is Bitwarden's
and the phone's doing; this has not been checked on a real iPhone.

## If something goes wrong

- **"That did not unlock your Bitwarden vault."** The master password was almost certainly typed wrong.
  Check that Caps Lock is off and run the same line again. After two tries, stop and check the password by
  signing in at vault.bitwarden.com.
- **Any other error:** send a screenshot of the window to the person who sent you the line.
- **A copy was trashed by mistake:** open the Trash in the Bitwarden web vault and restore it within 30 days.
- **Uninstall:** delete the folder `~/Library/Application Support/bw-health`.

## Privacy and safety

- The check-up and the previews only read your vault. Only `dedupe ... apply` and `fixurls apply` change
  it, each after its own typed word.
- No password, and no text from a note, is printed, logged or written to any file.
- Two things are fetched from the internet during the check-up, and neither names a site, a username or
  you: the breach check sends only a 5-character hash prefix, and the two-step check downloads the whole
  public [2FA Directory](https://2fa.directory/) list and compares it on your Mac. The list is kept for a
  day in your own bw-health folder, and the request carries nothing about you.
- No site in your vault is ever contacted. The links in the report are built from the address you saved
  and the entry's Bitwarden id, and are only followed when you click one. The report loads nothing from the
  internet: its styles and script are inside the file.
- The done ticks are kept in your browser's storage for that page, as Bitwarden ids only.
- The summary holds counts only, so it can be shared.
- To show what was fixed since last time, a small file next to the reports keeps each flagged item's
  Bitwarden id and the reason it was flagged. It holds no name, site, username or password.
- Reports and plain-text exports are kept out of the Desktop and iCloud, and you are told to trash the
  exports when done.
- Nothing is installed system-wide and no administrator password is needed. The Bitwarden command-line app
  is downloaded at a pinned version and its SHA-256 checksum is verified before it is used.
- The paste line names a released version. The files it fetches come from that release, and each is used
  only if its SHA-256 checksum matches the one written in the script.

## For maintainers

| File | Role |
| --- | --- |
| `bw-health.sh` | Entry point and installer (runs under the Mac's bash 3.2): installs uv and the pinned Bitwarden CLI, signs in once, runs the report, stages exports, or starts a dedupe step. |
| `bw_report.py` | The health report and the summary: every check in the table above, the links and the progress line, as one self-contained HTML page. Read-only. |
| `public_suffix_list.dat` | A pinned copy of the [Public Suffix List](https://publicsuffix.org/list/), so `co.uk` and `github.io` are read as shared endings when sites are grouped. Never fetched at run time from its source: update it by hand, with a new checksum and `VERSION`. |
| `fix_order.txt` | The one place the kinds of site are decided. One `tier domain`, `tier .ending` (such as `1 .gov`) or `tier folder: name` per line; a folder line wins, then a domain, then an ending. Edit it to add a site. |
| `bw_import_diff.py` | Compares Chrome and Apple exports with the vault and writes the import csv and `conflicts.md`. Read-only. |
| `bw_dedupe.py` | Duplicate cleanup and the AutoFill fix: the only code that edits or trashes vault items. It also holds the site grouping the report uses. |
| `tests/run.sh` | End-to-end tests with a stand-in `bw`; fixtures are in `tests/fixture`. |
| `tests/report_text.py` | Test-only: flattens a report page into lines the tests can search. |

- **Tests:** `bash tests/run.sh` on a Mac (needs `uv` and a network connection). CI runs it on a macOS
  runner for every push.
- **A release is a tag.** `bw-health.sh` names its `VERSION`, fetches its files from the tag `vVERSION`,
  and uses each only if it matches the SHA-256 written in `pinned_sha256`. Nothing is fetched from `main`.
- **Cutting a release.** The tag is pushed before `main` moves, and `main` then becomes that same
  commit, so no paste line ever points at a version whose tag does not exist yet:
  1. On the release branch, raise `VERSION` in `bw-health.sh` and the version in this README's paste
     lines. Run `bash tests/run.sh`: if a fetched file changed, it fails and prints the checksum line to
     paste into `pinned_sha256`. Run it again until it passes.
  2. Rebase the release branch onto the current `main` and run `bash tests/run.sh` on that exact commit.
  3. Tag that commit, `git tag vX.Y.Z <commit>`, and check the tag before it leaves the Mac: each line of
     `git show vX.Y.Z:bw-health.sh | grep -A5 '^pinned_sha256'` must equal `git show vX.Y.Z:<file> | shasum -a 256`.
  4. Push the tag: `git push origin vX.Y.Z`.
  5. Fast-forward `main` to the tagged commit and push it: `git merge --ff-only vX.Y.Z`, then
     `git push origin main`. Never squash, and never use a merge that makes a new commit: `main` must be
     the tagged commit itself.
  6. A tagged version never changes: once `vX.Y.Z` exists, the tests fail if `bw-health.sh` or a fetched
     file differs from it without a new `VERSION`.
- **Each run gets its own folder.** The fetched files go into a new folder under
  `~/Library/Application Support/bw-health` that is removed when the run ends, so two runs never mix versions.
- **Trying a branch before it is released:** run `bash bw-health.sh` from a checkout. Run as a file with
  all its files beside it, it uses those and says so; they are checked against the same checksums, so
  update a changed file's checksum first. `BW_HEALTH_BASE_URL` still overrides the source.
- **Bumping the Bitwarden CLI:** edit the version and the two SHA-256 values at the top of `bw-health.sh`,
  taking them from the digests of the `cli-v<version>` release assets.
- **What the tests cannot show:** how the real `bw` behaves. A new `bw` command or a change to a vault write
  should be tried first on one group (`apply 1`) against a real vault.
