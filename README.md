<h1 align="center">root@jomawii:~# password_checker.py</h1>

<p align="center">A command-line tool that evaluates password strength and gives feedback on how to improve it.</p>

<p align="center">
  <img src="https://img.shields.io/badge/-Python-000000?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/STATUS-FUNCTIONAL-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
  <img src="https://img.shields.io/badge/DATA-NEVER%20STORED-white?style=for-the-badge&labelColor=000000&color=FFFFFF" />
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=000000&height=2&section=header" width="100%"/>
</p>

## About

Scores a password from 0 (Very Weak) to 5 (Very Strong) based on length,
character variety, and whether it matches a list of widely known weak
passwords. Runs entirely locally - nothing is stored or sent anywhere.

## Features

- Strength score with a visual bar
- Checks for uppercase, lowercase, numbers, and special characters
- Flags common weak passwords (e.g. `password123`, `qwerty`)
- Estimates entropy (bits of randomness)
- Specific suggestions for improvement

## How to Run

Requires Python 3.

```
python3 password_checker.py
```

## Example

```
Enter a password to check: password123

Strength: Fair
[##---] 2/5
Estimated entropy: 56.9 bits

Suggestions:
  - Consider 12+ characters for stronger protection.
  - Add an uppercase letter.
  - Add a special character (e.g. ! @ # $ %).
```

## Why I Built This

I'm a cybersecurity student working toward becoming a Cloud Security
Analyst. This project was practice applying a real security concept
what actually makes a password resistant to guessing and brute-force
attacks while alsoo building out my Python fundamentals.

## Possible Future Improvements

- Check against a larger breached-password database (e.g. the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3))
- Add a web-based interface
- Support checking a list of passwords from a file
