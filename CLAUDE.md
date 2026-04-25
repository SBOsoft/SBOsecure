# NHI Manager — Claude Code Context

This file is read automatically by Claude Code at the start of every session.
Put things here that Claude should always know: conventions, constraints, patterns
that are non-obvious from reading the code, and commands needed to work in this repo.

---

## Project overview

**SBOsecure** is a single page application which allows users to create public key pairs and encrypt/decrypt or sign/verify files or content.
It's like a simple browser based PGP software but it uses only only javascript and windows subtle crypto.
---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Javascript |
| Framework | Vuejs 3 (options API) |
| Crypto | window.crypto.subtle |
| Containers | Docker Compose |



---

## Repository layout

```
DocumentRoot/
├── index.html               # Collector plugin system

containers/     # docker container for development
```

---


## What NOT to do
- Do not use additional external dependencies unless it's absolutely necessary


## Coding standards
- Write code that's easy to read and maintain
- Avoid functional style unless it's necessary
- Add brief documentation comments to functions unless they are short and self explanatory