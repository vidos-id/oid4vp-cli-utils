# PID Examples

These example files follow the SD-JWT VC PID claim mapping from the EUDI PID rulebook:
- base PID type namespace: `urn:eudi:pid:`
- common EU-wide base type example: `urn:eudi:pid:1`
- claim names use the SD-JWT VC mapping from Chapter 4 of the PID rulebook

Included examples:
- `pid-minimal.claims.json` - mandatory PID attributes plus core metadata
- `pid-full.claims.json` - a broader PID example with optional attributes
- `pid-basic-request.json` - a small DCQL request for a PID
- `pid-address-request.json` - a DCQL request for address-focused PID claims
- `pid-basic.openid4vp.txt` - an `openid4vp://` URL carrying the same basic PID DCQL request by value

Use these files with the installed CLIs from the repo root, for example `./issuer-cli issue --claims-file examples/pid/pid-minimal.claims.json`.

For development in this repo, the same flow can be run directly with Bun via `bun packages/issuer-cli/src/index.ts` and `bun packages/wallet-cli/src/index.ts`.

Notes:
- use `birthdate`, not `birth_date`
- use `nationalities`, not `nationality`
- use `place_of_birth` object
- use `address.*` members for resident address fields
- use `date_of_expiry` / `date_of_issuance` for PID metadata in SD-JWT VC form
- `openid4vp://` examples in this repo are by-value and keep only the supported demo subset
