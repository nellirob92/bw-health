# bw-health

A one-line password check-up for a Bitwarden vault, for family members on a Mac. It finds passwords that
are exposed in a breach, reused, weak or saved twice, helps you move old Chrome and Apple passwords in, and
can tidy duplicate entries. It works on the free Bitwarden plan.

- [Run the check-up](#run-the-check-up)
- [Move your old passwords in](#move-your-old-passwords-in)
- [Several people on one Mac](#several-people-on-one-mac)
- [Clean up duplicates](#clean-up-duplicates)
- [If something goes wrong](#if-something-goes-wrong)
- [Privacy and safety](#privacy-and-safety)
- [For maintainers](#for-maintainers)

## Run the check-up

Open Terminal (press Command-Space, type `Terminal`, press Return), paste this line, press Return:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.0.0/bw-health.sh | bash
```

It asks for your Bitwarden email (the first time only), your master password, and the two-step code if
Bitwarden asks for one. Nothing shows on the screen while you type the password. It then opens the report
in your browser.

**This check only reads your vault.** It never merges, deletes or changes anything, and no password is
ever shown. It locks your vault again when it finishes.

| The report lists | Meaning |
| --- | --- |
| Fixed since last time | From the second run on: how many flagged items were fixed, how many are left, and which are new. |
| Fix in this order | Email and Apple, Google and Microsoft accounts first, then money, then phone, utilities, insurance and health, then gaming and social, then everything else. Each login has links to its change-password page, its site and its Bitwarden entry. |
| Exposed in a breach | The password appears in public breach lists. Only the first 5 characters of its SHA-1 hash leave your Mac (Have I Been Pwned's range check). |
| Reused | The same password is used on more than one account. |
| Weak | The password is short or predictable. |
| Duplicate entries | The same site and username is saved more than once. |
| Two-step login | The site offers two-step login and no code is saved in the entry. Check that it is turned on at the site: the entry cannot show that. "Supports" means the saved address is on the public list; "likely supports" means only a related address is. If the list cannot be downloaded, the section says "not checked this run". |
| AutoFill problems | The entry has no web address, or only an `http://` one, so iPhone AutoFill will not offer it reliably. |
| Unchanged for 3+ years | The password has not changed in three years. Importing resets these dates, so this only means something on later runs. |
| Notes that may hold a password | A note with a line like `password: ...`. Only the item's name is shown, never the note. |
| Your Bitwarden account | Links to check that your Bitwarden email is verified and two-step login is on. The check-up cannot see either. |

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
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.0.0/bw-health.sh | bash -s -- --user mom
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

## Clean up duplicates

Importing from both Chrome and Apple usually leaves two copies of the same login. Cleaning them up is a
**separate step that you start yourself**, and by default it is a **preview that changes nothing**. It only
changes your vault when you add `apply` and then type `DEDUPE` after reading the full list.

Add the words after `bash -s --` on the paste line, for example:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/v1.0.0/bw-health.sh | bash -s -- dedupe merge
```

| Add this | What happens |
| --- | --- |
| `dedupe exact` | Preview: copies that are identical in every field. |
| `dedupe merge` | Preview: copies with the same password (or a missing one) whose details differ. |
| `dedupe pick` | Preview: copies whose only conflict is different passwords, each listed newest password first with its dates. |
| `dedupe exact apply` or `dedupe merge apply` | Acts on the preview, after you read the list and type `DEDUPE`. |
| `dedupe pick apply` | Asks, group by group, which password works (type its number; Enter skips the group), then acts after `DEDUPE`. |
| `... apply 10` | Acts on only the first 10 groups. Start with `apply 1`. |

**What it does to a group of copies.** One copy is kept. It gains the other copies' URLs (the same site
written differently counts once), notes, custom fields, one-time-code seed, a missing password, and a
favorite or master password re-prompt setting that any copy has turned on. The other
copies go to Bitwarden's Trash, where they stay for 30 days and can be restored. Nothing is ever deleted
permanently. Only the kept copy's name and folder survive.

**Passkeys.** A copy that holds a passkey is always the one kept, because a passkey cannot be moved. After
every edit the kept copy is read back from Bitwarden, and the run stops before trashing anything if what
was saved differs from what was sent. The read-back can detect a damaged passkey but cannot undo it, so keep
the original in Apple Passwords or Chrome until you have checked that entry in Bitwarden.

**Different passwords (`dedupe pick`).** Copies are ranked by when their password was set: its last change,
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

## If something goes wrong

- **"That did not unlock your Bitwarden vault."** The master password was almost certainly typed wrong.
  Check that Caps Lock is off and run the same line again. After two tries, stop and check the password by
  signing in at vault.bitwarden.com.
- **Any other error:** send a screenshot of the window to the person who sent you the line.
- **A copy was trashed by mistake:** open the Trash in the Bitwarden web vault and restore it within 30 days.
- **Uninstall:** delete the folder `~/Library/Application Support/bw-health`.

## Privacy and safety

- The check-up and the previews only read your vault. Only `dedupe ... apply` changes it, after a typed
  confirmation.
- No password, and no text from a note, is printed, logged or written to any file.
- Two things are fetched from the internet during the check-up, and neither names a site, a username or
  you: the breach check sends only a 5-character hash prefix, and the two-step check downloads the whole
  public [2FA Directory](https://2fa.directory/) list and compares it on your Mac. The list is kept for a
  day in your own bw-health folder, and the request carries nothing about you.
- No site in your vault is ever contacted. The links in the report are built from the address you saved.
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
| `bw_report.py` | The health report: every check in the table above, the links and the progress line. Read-only. |
| `fix_order.txt` | Which sites and Bitwarden folders are fixed first. One `tier domain` or `tier folder: name` per line; edit it to add a site. |
| `bw_import_diff.py` | Compares Chrome and Apple exports with the vault and writes the import csv and `conflicts.md`. Read-only. |
| `bw_dedupe.py` | Duplicate cleanup: the only code that edits or trashes vault items. |
| `tests/run.sh` | End-to-end tests with a stand-in `bw`; fixtures are in `tests/fixture`. |

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
- **Trying a branch before it is released:** run `bash bw-health.sh` from a checkout. Run as a file with
  its four files beside it, it uses those and says so; they are checked against the same checksums, so
  update a changed file's checksum first. `BW_HEALTH_BASE_URL` still overrides the source.
- **Bumping the Bitwarden CLI:** edit the version and the two SHA-256 values at the top of `bw-health.sh`,
  taking them from the digests of the `cli-v<version>` release assets.
- **What the tests cannot show:** how the real `bw` behaves. A new `bw` command or a change to a vault write
  should be tried first on one group (`apply 1`) against a real vault.
