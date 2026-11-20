# Backlog

Work that was considered and left out, with the reason.

- **A `BW_HEALTH_USER` environment variable as a second way to name a profile.** Left out on purpose:
  a variable that lingers in a Terminal tab is how one person's run lands in another person's profile.
  `--user NAME` on the line is the only way.
- **A step that deletes a profile's folders** (sign-in data, import folder, dedupe plan). `logout` signs
  out and points at leftover import files, but removing them is still done by hand in Finder.
- **A check of `logout` and `--logout-after` against the real Bitwarden command-line app.** The tests use
  a stand-in; the first real sign-out is the check.
- **The Desktop report of a profile is not removed by `logout`.** It lists site names and usernames (never
  passwords) and stays until it is trashed by hand.
