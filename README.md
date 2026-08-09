<h1 align="center">root@jomawii:~# password_checker.py</h1>

<p align="center">A command-line tool that scores password strength and explains exactly why, using length, character variety, entropy estimation, and a 147-entry common-password wordlist.</p>

<p align="center">
  <img src="https://img.shields.io/badge/-Python%203-000000?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/STATUS-FUNCTIONAL-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
  <img src="https://img.shields.io/badge/DEPENDENCIES-NONE-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
  <img src="https://img.shields.io/badge/DATA-NEVER%20STORED-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
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
- [A Note on Entropy](#a-note-on-entropy)
- [Security Notes](#security-notes)
- [Limitations](#limitations)
- [Why I Built This](#why-i-built-this)
- [Possible Future Improvements](#possible-future-improvements)

## About

Scores a password from 0 (Very Weak) to 5 (Very Strong) based on length,
character variety, and whether it matches a wordlist of widely known weak
passwords. Runs entirely locally nothing is stored, logged, or sent
anywhere.

## Features

- Strength score (0-5) with a visual bar
- Checks for uppercase, lowercase, numbers, and special characters
- Flags passwords against a 147-entry common-password wordlist
- Estimates entropy (bits of randomness) see the note below on what this does and doesn't measure
- Specific, actionable suggestions for improvement
- Hidden password input (via `getpass`) nothing is echoed to the terminal
- Falls back to a small built-in wordlist if `common_passwords.txt` isn't found, so the tool never breaks

## Project Structure

```
password-strength-checker/
├── password_checker.py     # main script
├── common_passwords.txt    # wordlist of known weak passwords
├── .gitignore
└── README.md
```

## How to Run

Requires Python 3. No external dependencies.

```bash
python3 password_checker.py
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

(The password itself isn't echoed to the terminal as you type — that's `getpass` doing its job.)

## How Scoring Works

| Criteria | Points |
|---|---|
| Length >= 8 characters | +1 |
| Length >= 12 characters | +1 |
| 3 or more character types present (lower/upper/digit/special) | +1 |
| All 4 character types present | +1 |
| Not found in the common-password wordlist | +1 |
| **Maximum score** | **5** |

If a password matches an entry in the wordlist, it's scored **0** immediately, regardless of length or complexity — a common password with symbols swapped in is still a common password.

## A Note on Entropy

The entropy number this tool shows is a rough theoretical estimate, not a
real measurement of how hard a password is to crack. It assumes
characters were chosen randomly from whatever character types are
detected (lowercase, uppercase, digits, symbols). Real human passwords
aren't random something like `Jomari123!` can score a decent
theoretical entropy here while still being predictable, since it follows
a common pattern (name + number + symbol). Treat the entropy number as a
loose signal alongside the score, not a guarantee of strength.

## Security Notes

- Password input uses `getpass`, so it's never displayed or echoed in the terminal
- The password is only ever held in memory for the duration of the check it is never written to disk, logged, or transmitted over a network
- The wordlist check is case-insensitive but otherwise exact-match it will not catch every variation of a weak password (see Limitations)

## Limitations

- The common-password wordlist has 147 entries useful for catching the most obvious weak passwords, but far smaller than real-world breached-password databases with millions of entries
- Entropy is a theoretical estimate, not a measure of real-world guessability (see [above](#a-note-on-entropy))
- No check for patterns like keyboard walks (`qwertyasdf`) or personal information (birthdays, names) beyond what's in the wordlist

## Why I Built This

I'm a cybersecurity student working toward becoming a Cloud Security
Analyst. This project was practice applying a real security concept
what actually makes a password resistant to guessing and brute-force
attacks while building out my Python fundamentals.

## Possible Future Improvements

- Check against a larger breached-password database (e.g. the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3))
- Detect keyboard-walk patterns and personal-info-based passwords
- Add a web-based interface
- Support checking a list of passwords from a file

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=000000&height=2&section=header" width="100%"/>
</p>

<p align="center">
  <a href="https://github.com/jomawii"><img src="https://img.shields.io/badge/-GitHub_Profile-000000?style=for-the-badge&logo=github&logoColor=white" /></a>
  <a href="https://www.linkedin.com/in/jomari-miranda-663892377"><img src="https://img.shields.io/badge/-LinkedIn-000000?style=for-the-badge&logo=linkedin&logoColor=white" /></a>
</p>
