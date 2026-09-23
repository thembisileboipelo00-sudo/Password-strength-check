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
