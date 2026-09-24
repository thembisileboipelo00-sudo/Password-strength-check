# Password Strength & Breach Checker

A small command-line tool written in Java that evaluates a password two ways:

1. **Entropy estimation** — how many bits of randomness the password
   represents, based on character-set size and length.
2. **Local breach-list lookup** — whether the password appears in a small
   offline list of commonly leaked passwords.

No password is ever sent over the network. The breach list is a static
local file (`data/common_passwords.txt`), not a live API — this was a
deliberate choice so the tool is safe to run and doesn't leak whatever
you type into it.

## Demo video
[Link to 5–10 min YouTube demo — add after recording]

## Why these two checks are kept separate

A password can look random (high entropy) and *still* be in a known leak —
entropy only measures theoretical brute-force difficulty, it says nothing
about whether that exact string has already been exposed. Combining both
into one blended "score" would hide that distinction, so the tool reports
them independently and lets the suggestions section explain what to do
about each.

## How entropy is calculated

```
entropy (bits) = password length × log2(character pool size)
```

The character pool grows by 26 for lowercase, 26 for uppercase, 10 for
digits, and ~32 for symbols, depending on which classes are actually
present in the password. This is the standard "worst-case brute force"
estimate used in most password-strength literature.

**Known limitation:** this formula assumes the password was chosen
uniformly at random from that pool. Real passwords aren't — `Password1!`
has high formula-entropy but is a predictable pattern a real attacker
would try early. That's part of why the breach-list check exists as a
second, independent signal rather than relying on entropy alone.

## Project structure

```
password-checker/
├── src/
│   └── PasswordChecker.java   # all logic: entropy calc, breach check, CLI
├── data/
│   └── common_passwords.txt   # small local sample breach list
└── README.md
```

## How to run

Requires a JDK (Java 11+).

```bash
cd password-checker
javac -d out src/PasswordChecker.java
cd out
java -cp . PasswordChecker
```

> Note: the program looks for `data/common_passwords.txt` relative to
> where you run it from. Run `java` from the `password-checker/` root
> if you see a "could not load breach list" warning, or adjust the
> path in `PasswordChecker.java`.

## Example output

```
=== Password Strength & Breach Checker ===
Enter a password to test: qwerty123

--- Results ---
Length:            9 characters
Estimated entropy: 32.9 bits
Strength rating:   Weak
Found in breach list: YES — do not use this password

--- Suggestions ---
- This exact password is known to be leaked. Change it everywhere you use it.
- Use at least 12 characters; length matters more than complexity tricks.
- Mix uppercase, lowercase, digits, and symbols to widen the character pool.
```

## Possible future improvements

- Detect keyboard-walk patterns (e.g. `qwerty`, `1qaz2wsx`) explicitly,
  since entropy alone doesn't catch these.
- Swap the static breach list for a k-anonymity lookup against the
  Have I Been Pwned API (never sending the full password/hash).
- Add unit tests for `calculateEntropyBits` and `classifyStrength`.

## Author's note

Built as a solo project for the Cybersecurity elective. Every design
decision above — separating entropy from breach-checking, keeping the
breach list local instead of calling an API, the entropy formula and its
limitation — was a deliberate choice I can walk through and justify.
