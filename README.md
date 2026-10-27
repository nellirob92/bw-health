# bw-health

A one-line password check-up for a Bitwarden vault, for family members on a Mac. It finds passwords that
are exposed in a breach, reused, weak or saved twice, helps you move old Chrome and Apple passwords in, and
can tidy duplicate entries. It works on the free Bitwarden plan.

- [Run the check-up](#run-the-check-up)
- [Move your old passwords in](#move-your-old-passwords-in)
- [Clean up duplicates](#clean-up-duplicates)
- [If something goes wrong](#if-something-goes-wrong)
- [Privacy and safety](#privacy-and-safety)
- [For maintainers](#for-maintainers)

## Run the check-up

Open Terminal (press Command-Space, type `Terminal`, press Return), paste this line, press Return:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/main/bw-health.sh | bash
```

It asks for your Bitwarden email (the first time only), your master password, and the two-step code if
Bitwarden asks for one. Nothing shows on the screen while you type the password. It then opens a report
called `Bitwarden Report.html` on your Desktop.

**This check only reads your vault.** It never merges, deletes or changes anything, and no password is
ever shown. It locks your vault again when it finishes.

| The report lists | Meaning |
| --- | --- |
| Exposed in a breach | The password appears in public breach lists. Only the first 5 characters of its SHA-1 hash leave your Mac (Have I Been Pwned's range check). |
| Reused | The same password is used on more than one account. |
| Weak | The password is short or predictable. |
| Duplicate entries | The same site and username is saved more than once. |
| Fix in this order | Email, Apple and Google accounts first, then money, then gaming and social, then everything else. |

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

## Clean up duplicates

Importing from both Chrome and Apple usually leaves two copies of the same login. Cleaning them up is a
**separate step that you start yourself**, and by default it is a **preview that changes nothing**. It only
changes your vault when you add `apply` and then type `DEDUPE` after reading the full list.

Add the words after `bash -s --` on the paste line, for example:

```
curl -fsSL https://raw.githubusercontent.com/nellirob92/bw-health/main/bw-health.sh | bash -s -- dedupe merge
```

| Add this | What happens |
| --- | --- |
| `dedupe exact` | Preview: copies that are identical in every field. |
| `dedupe merge` | Preview: copies with the same password (or a missing one) whose details differ. |
| `dedupe exact apply` or `dedupe merge apply` | Acts on the preview, after you read the list and type `DEDUPE`. |
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

**Left alone, and listed with the reason:** copies with different passwords or different one-time-code
seeds, a custom field with two values, an attachment, several passkeys (or one Bitwarden listed without its
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
- No password is printed, logged or written to a plan file. The breach check sends only a 5-character hash
  prefix.
- Plain-text exports are kept out of the Desktop and iCloud, and you are told to trash them when done.
- Nothing is installed system-wide and no administrator password is needed. The Bitwarden command-line app
  is downloaded at a pinned version and its SHA-256 checksum is verified before it is used.

## For maintainers

| File | Role |
| --- | --- |
| `bw-health.sh` | Entry point and installer (runs under the Mac's bash 3.2): installs uv and the pinned Bitwarden CLI, signs in once, runs the report, stages exports, or starts a dedupe step. |
| `bw_report.py` | The health report (exposed, reused, weak, duplicate). Read-only. |
| `bw_import_diff.py` | Compares Chrome and Apple exports with the vault and writes the import csv and `conflicts.md`. Read-only. |
| `bw_dedupe.py` | Duplicate cleanup: the only code that edits or trashes vault items. |
| `tests/run.sh` | End-to-end tests with a stand-in `bw`; fixtures are in `tests/fixture`. |

- **Tests:** `bash tests/run.sh` on a Mac (needs `uv` and a network connection). CI runs it on a macOS
  runner for every push.
- **A merge to `main` is a release:** the paste line fetches the scripts from `main` on every run.
- **Bumping the Bitwarden CLI:** edit the version and the two SHA-256 values at the top of `bw-health.sh`,
  taking them from the digests of the `cli-v<version>` release assets.
- **What the tests cannot show:** how the real `bw` behaves. A new `bw` command or a change to a vault write
  should be tried first on one group (`apply 1`) against a real vault.
