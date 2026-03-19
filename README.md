# oid4vp-cli-utils

Lightweight Bun/TypeScript demo utilities for:
- issuing holder-bound `dc+sd-jwt` credentials through a minimal OpenID4VCI-style flow
- storing and presenting those credentials through a minimal OpenID4VP DCQL flow

Workspace packages:
- `packages/issuer` - issuer library
- `packages/wallet` - wallet library
- `packages/issuer-cli` - issuer CLI
- `packages/wallet-cli` - wallet CLI

## Install

```bash
bun install
```

## Validate

```bash
bun test
bun run check-types
bun run lint
```

## Run The End-To-End Demo

```bash
bun scripts/demo-e2e.ts
```

The script:
- generates issuer trust material
- issues a holder-bound `dc+sd-jwt`
- imports it into file-backed wallet storage
- creates a DCQL-based presentation

## Example Inputs

Reusable example payloads live in `examples/pid/`.

- `examples/pid/pid-minimal.claims.json` - minimal PID-style SD-JWT VC claims
- `examples/pid/pid-full.claims.json` - broader PID-style SD-JWT VC claims
- `examples/pid/pid-basic-request.json` - basic PID DCQL request
- `examples/pid/pid-address-request.json` - address-focused PID DCQL request
- `examples/pid/pid-basic.oid4vp.txt` - by-value `oid4vp://` authorization URL example

## CLI Quick Start

Generate issuer trust material:

```bash
bun packages/issuer-cli/src/index.ts generate-trust-material \
  --trust-artifact-out .demo/trust.json \
  --private-jwk-out .demo/private.jwk.json \
  --public-jwk-out .demo/public.jwk.json \
  --jwks-out .demo/jwks.json \
  --certificate-out .demo/issuer.crt.pem
```

Issue a credential:

```bash
bun packages/issuer-cli/src/index.ts issue \
  --issuer https://issuer.example \
  --signing-key-file .demo/trust.json \
  --vct https://example.com/PersonCredential \
  --claims '{"given_name":"Ada","family_name":"Lovelace"}' \
  --proof-file .demo/proof.jwt \
  --output raw
```

Import it into the wallet:

```bash
bun packages/wallet-cli/src/index.ts import \
  --wallet-dir .demo/wallet \
  --credential-file .demo/credential.txt \
  --issuer https://issuer.example \
  --issuer-jwks-file .demo/jwks.json
```

Create a presentation:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request-file .demo/request.json
```

Create a presentation from an `oid4vp://` authorization URL:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request-file examples/pid/pid-basic.oid4vp.txt
```

If multiple stored credentials match the DCQL request, `wallet-cli present` now prompts interactively for which credential to use unless you pass `--credential-id`.

## Notes

- demo/internal only
- `dc+sd-jwt` only
- DCQL only, no Presentation Exchange
- `oid4vp://` support is limited to by-value requests carrying `client_id`, `nonce`, and `dcql_query`
- wallet trust store for verifiers/readers is out of scope
- issuer certificate artifacts are for external verifier trust bootstrapping; wallet verification uses JWK/JWKS-oriented material
