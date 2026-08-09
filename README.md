<h1 align="center">root@jomawii:~# password_checker.py</h1>

<p align="center">A command-line tool that scores password strength and explains exactly why, using length, character variety, pattern detection, entropy estimation, a 147-entry common-password wordlist, and an optional real breach check against the Have I Been Pwned database.</p>

<p align="center">
  <img src="https://img.shields.io/badge/-Python%203-000000?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/STATUS-FUNCTIONAL-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
  <img src="https://img.shields.io/badge/DEPENDENCIES-NONE-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
  <img src="https://img.shields.io/badge/TESTS-20%20PASSING-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=000000&height=2&section=header" width="100%"/>
</p>

## Table of Contents

- [About](#about)
- [Features](#features)
- [Project Structure](#project-structure)
- [How to Run](#how-to-run)
- [Example](#example)
- [How Scoring Works](#how-scoring-works)
- [The Breach Check (Have I Been Pwned)](#the-breach-check-have-i-been-pwned)
- [A Note on Entropy](#a-note-on-entropy)
- [Security Notes](#security-notes)
- [Running the Tests](#running-the-tests)
- [Limitations](#limitations)
- [Why I Built This](#why-i-built-this)
- [Possible Future Improvements](#possible-future-improvements)

## About

Scores a password from 0 (Very Weak) to 5 (Very Strong) based on length,
character variety, predictable patterns, and whether it matches a
wordlist of widely known weak passwords - with an optional real check
against billions of breached passwords via the Have I Been Pwned API.

## Features

- Strength score (0-5) with a visual bar
- Checks for uppercase, lowercase, numbers, and special characters
- Detects leetspeak substitutions (`P@ssw0rd` is still caught as a variant of `password`)
- Detects keyboard walks (`qwerty`, `asdf`), sequential runs (`abc`, `123`), and repeated characters (`aaa`)
- Flags passwords against a 147-entry common-password wordlist
- Optional real breach check via the Have I Been Pwned API (k-anonymity - see below)
- Estimates entropy (bits of randomness) - see the note below on what this does and doesn't measure
- Batch mode: check a whole file of passwords at once with `--file`
- Specific, actionable suggestions for improvement
- Hidden password input (via `getpass`) - nothing is echoed to the terminal
- 20 unit tests covering scoring, pattern detection, and the breach check (network calls are mocked)
- Falls back to a small built-in wordlist if `common_passwords.txt` isn't found, so the tool never breaks

## Project Structure

```
password-strength-checker/
|---- password_checker.py       # main script
|---- test_password_checker.py  # unit tests
|---- common_passwords.txt      # wordlist of known weak passwords
|---- .gitignore
`---- README.md
```

## How to Run

Requires Python 3. No external dependencies.

```bash
python3 password_checker.py
```

Check a whole file of passwords at once (one per line):

```bash
python3 password_checker.py --file passwords.txt
```

> **Warning:** Never use real passwords or credentials in a batch file,
> especially if that file might end up committed to this repo. Use
> synthetic test passwords only. Add any local password test files to
> `.gitignore` before creating them.

Skip the online breach check and run fully offline:

```bash
python3 password_checker.py --no-pwned
```

## Example

```
Enter a password to check: 

Strength: Fair
[##---] 2/5
Estimated entropy: 56.9 bits

Suggestions:
  - Consider 12+ characters for stronger protection.
  - Add an uppercase letter.
  - Add a special character (e.g. ! @ # $ %).
```

(The password itself isn't echoed to the terminal as you type - that's `getpass` doing its job.)

## How Scoring Works

| Criteria | Points |
|---|---|
| Length >= 8 characters | +1 |
| Length >= 12 characters | +1 |
| 3 or more character types present (lower/upper/digit/special) | +1 |
| All 4 character types present | +1 |
| Not found in the common-password wordlist | +1 |
| Predictable pattern detected (keyboard walk, sequential, repeated) | -1 |
| **Maximum score** | **5** |

If a password matches an entry in the wordlist (including leetspeak
variants) or shows up in the breach check, it's scored **0** immediately,
regardless of length or complexity - a common or breached password with
symbols swapped in is still a common or breached password.

## The Breach Check (Have I Been Pwned)

By default, the tool checks the password against the
[Have I Been Pwned](https://haveibeenpwned.com/) breach database, which
tracks passwords exposed in real-world data breaches.

This is done using **k-anonymity**, so your actual password is never
sent anywhere:

1. The password is hashed locally with SHA-1
2. Only the **first 5 characters** of that hash are sent to the API
3. The API returns every breached hash suffix that starts with those 5 characters (often hundreds of matches)
4. The full comparison happens locally on your machine

The full password, and even the full hash, never leave your device -
only a 5-character prefix that thousands of other hashes also share.
Use `--no-pwned` to skip this and run the tool fully offline.

## A Note on Entropy

The entropy number this tool shows is a rough theoretical estimate, not a
real measurement of how hard a password is to crack. It assumes
characters were chosen randomly from whatever character types are
detected (lowercase, uppercase, digits, symbols). Real human passwords
aren't random - something like `Jomari123!` can score a decent
theoretical entropy here while still being predictable, since it follows
a common pattern (name + number + symbol). Treat the entropy number as a
loose signal alongside the score, not a guarantee of strength.

## Security Notes

- Password input uses `getpass`, so it's never displayed or echoed in the terminal
- The password itself is only ever held in memory for the duration of the check - it is never written to disk or logged
- The breach check only ever transmits a 5-character hash prefix, never the password or full hash (see above) - and it's entirely optional via `--no-pwned`
- The wordlist check is case-insensitive and leetspeak-aware, but otherwise exact-match - it will not catch every variation of a weak password (see Limitations)

## Running the Tests

The project includes 20 unit tests covering scoring logic, pattern
detection, and the breach check (the network call is mocked, so tests
run instantly with no internet required):

```bash
python3 -m unittest test_password_checker.py -v
```

## Limitations

- The common-password wordlist has 147 entries - useful for catching the most obvious weak passwords, but far smaller than the Have I Been Pwned database, which is why the breach check exists as a second layer
- The breach check requires an internet connection; if it can't be reached, the tool says so and falls back to the offline checks only
- Entropy is a theoretical estimate, not a measure of real-world guessability (see [above](#a-note-on-entropy))
- Keyboard-walk detection only covers the standard QWERTY rows and number row, not every possible layout

## Why I Built This

I'm a cybersecurity student working toward becoming a Cloud Security
Analyst. This project was practice applying real security concepts -
what actually makes a password resistant to guessing and brute-force
attacks, and how k-anonymity lets you check a password against a breach
database without exposing it - while building out my Python
fundamentals and testing practices.

## Possible Future Improvements

- Expand the local wordlist significantly
- Add a web-based interface
- Support additional keyboard layouts in pattern detection

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=000000&height=2&section=header" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/jomawii"><img src="https://img.shields.io/badge/-GitHub_Profile-000000?style=for-the-badge&logo=github&logoColor=white" /></a>
  <a href="https://www.linkedin.com/in/jomari-miranda-663892377"><img src="https://img.shields.io/badge/-LinkedIn-000000?style=for-the-badge&logo=linkedin&logoColor=white" /></a>
</p>
