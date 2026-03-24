# PID Examples

These example files follow the SD-JWT VC PID claim mapping from the EUDI PID rulebook:
- base PID type namespace: `urn:eudi:pid:`
- common EU-wide base type example: `urn:eudi:pid:1`
- claim names use the SD-JWT VC mapping from Chapter 4 of the PID rulebook

Included examples:
- `pid-minimal.claims.json` - mandatory PID attributes plus core metadata - `https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-minimal.claims.json`
- `pid-full.claims.json` - a broader PID example with optional attributes - `https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-full.claims.json`
- `pid-basic-request.json` - a small DCQL request for a PID - `https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-basic-request.json`
- `pid-address-request.json` - a DCQL request for address-focused PID claims - `https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-address-request.json`
- `pid-basic.openid4vp.txt` - an `openid4vp://` URL carrying the same basic PID DCQL request by value - `https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-basic.openid4vp.txt`

If you cloned the repo, use the local files directly, for example `./issuer-cli issue --claims-file examples/pid/pid-minimal.claims.json`.

If you only downloaded the release CLIs, fetch the same inputs from raw GitHub, for example `./issuer-cli issue --claims "$(curl -fsSL https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-minimal.claims.json)"`.

For development in this repo, the same flow can be run directly with Bun via `bun packages/issuer-cli/src/index.ts` and `bun packages/wallet-cli/src/index.ts`.

Notes:
- use `birthdate`, not `birth_date`
- use `nationalities`, not `nationality`
- use `place_of_birth` object
- use `address.*` members for resident address fields
- use `date_of_expiry` / `date_of_issuance` for PID metadata in SD-JWT VC form
- `openid4vp://` examples in this repo are by-value and keep only the supported demo subset
