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
- `pid-basic.oid4vp.txt` - an `oid4vp://` URL carrying the same basic PID DCQL request by value

Notes:
- use `birthdate`, not `birth_date`
- use `nationalities`, not `nationality`
- use `place_of_birth` object
- use `address.*` members for resident address fields
- use `date_of_expiry` / `date_of_issuance` for PID metadata in SD-JWT VC form
- `oid4vp://` examples in this repo are by-value and keep only the supported demo subset
