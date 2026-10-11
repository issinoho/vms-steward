# Idea: a layout made for phones

**Asked for by the user, 2026-10-11:** "the site is better suited to use from a mobile
phone. It's currently not user friendly." Not scheduled yet: on the wish list.

## What the user saw (0.4.0 on a phone, My account)

- **The navigation** is the desktop sidebar turned into one row of eight links. Each
  wraps onto two lines ("MY / ACCOUNT", "RIGHTS / IDENTIFIERS"). The row scrolls
  sideways, with nothing to show there is more off-screen, and it takes about a fifth of
  the screen before any content.
- **Theme and Sign out** sit on a bar of their own beneath it, a second strip of chrome.
- **The prompt line** (`$ show process IAIN [200,101]`) is gone at this width, so it no
  longer says who you are.
- **The keycap lists** (default privileges: 38 caps for SYSTEM-like accounts) fill a
  whole screen.
- **Wide tables** (users, access history, logical names) scroll inside their box, which
  works but is hard to read. Rows would read better as stacked cards.
- **Touch targets** are small: links of 0.75rem uppercase monospace, close together.

## Directions to consider

- **Navigation:** a compact top bar (the `$ steward` wordmark, the current area, a menu
  button) opening a full-height menu of the areas. Or a bottom tab bar for the four or
  five most used areas, with "More" for the rest.
- **One header:** the user, theme and sign out in the menu, not on a bar of their own.
- **Lists:** below about 720px, each row a card. The key field is large (username,
  name, when), and the rest go in two columns of label and value.
- **Keycaps:** collapse long lists to the first row and a "+N more" toggle.
- **Filters:** the DCL command lines stack their qualifiers one per line, with full-width
  inputs and a full-width Show button.
- **Touch:** 44px minimum targets, and nothing that needs hover.
- **Checking:** headless screenshots at 360, 390 and 430px for every view in the exit
  checks, and on a real phone through nginx proxy manager.

The DEC character should stay: the keycaps, the amber terminal lines, the mono labels.
On a phone they should simply be fewer and larger.
