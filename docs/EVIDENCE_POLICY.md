# Evidence policy

## Evidence classes

1. **Official primary source** — platform/vendor documentation or first-party engineering statement.
2. **Retail observation** — repeatable behavior captured from an owned retail build.
3. **Binary observation** — strings, imports, control flow, or runtime behavior from lawful local inspection.
4. **Independent secondary source** — credible external research that guides, but does not replace, MCC evidence.
5. **Hypothesis** — plausible claim awaiting evidence.

## Commit rules

Allowed:

- SHA-256 hashes and non-secret metadata
- Redacted request/response schemas
- Synthetic fixtures
- Domain and endpoint names
- Tooling written for this project
- Analysis notes and reproducible commands

Forbidden:

- Live OAuth, Xbox user, XSTS, Spartan, Steam, session, or refresh tokens
- Passwords, cookies, private keys, client certificates, or CA private material
- Raw PCAP/HAR/SAZ files containing identifiers or credentials
- Retail executables, DLLs, maps, tags, depots, or game assets
- Other players' personal data

## Claim format

Each report records:

- Claim
- Evidence IDs
- Reproduction steps
- Counter-evidence
- Confidence
- Authorized next action
