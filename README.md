# oid4vp-cli-utils

CLI tools for quick `dc+sd-jwt` credential issuance, holding, and OpenID4VP presentation.

Built for simple, scriptable credential flows -- primarily created as a PoC for making wallet operations CLI-consumable so they can be driven by AI agents like [OpenClaw](https://github.com/anthropics/openclaw) 🦞.

## Packages

| Package | Description |
|---------|-------------|
| [`issuer-cli`](packages/issuer-cli/) | Issue credentials and manage issuer key material |
| [`wallet-cli`](packages/wallet-cli/) | Hold credentials and create OpenID4VP presentations |
| [`issuer`](packages/issuer/) | Issuer library (used by issuer-cli) |
| [`wallet`](packages/wallet/) | Wallet library (used by wallet-cli) |

## Quick Start

The full issue-hold-present flow in 4 commands:

```bash
# 1. Initialize wallet (creates holder key)
bun packages/wallet-cli/src/index.ts init \
  --wallet-dir .demo/wallet

# 2. Initialize issuer (generates signing key, JWKS, trust material)
bun packages/issuer-cli/src/index.ts init \
  --issuer-dir .demo/issuer

# 3. Issue a holder-bound credential
bun packages/issuer-cli/src/index.ts issue \
  --issuer-dir .demo/issuer \
  --holder-key-file .demo/wallet/holder-key.json \
  --issuer https://issuer.example \
  --vct urn:eudi:pid:1 \
  --credential-file credential.txt \
  --claims-file examples/pid/pid-minimal.claims.json

# 4. Import credential into the wallet
bun packages/wallet-cli/src/index.ts import \
  --wallet-dir .demo/wallet \
  --credential-file .demo/issuer/credential.txt
```

Then present it:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request '{"client_id":"https://verifier.example","nonce":"n-1","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}}'
```

Or from an `openid4vp://` authorization URL:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request 'openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&nonce=n-1&response_type=vp_token&dcql_query=...'
```

See [`issuer-cli`](packages/issuer-cli/) and [`wallet-cli`](packages/wallet-cli/) for full command reference.

## Algorithms

Supports ES256, ES384, and EdDSA throughout. Both CLIs accept `--alg` to choose:

```bash
# Issuer with ES256
bun packages/issuer-cli/src/index.ts init --issuer-dir .demo/issuer --alg ES256

# Wallet with EdDSA
bun packages/wallet-cli/src/index.ts init --wallet-dir .demo/wallet --alg EdDSA
```

Defaults: EdDSA for issuer signing, ES256 for wallet holder keys.

You can also import existing key material instead of generating:

```bash
# Import a PEM or JWK private key (algorithm auto-detected)
bun packages/issuer-cli/src/index.ts import-trust-material \
  --issuer-dir .demo/issuer \
  --private-key ./private-key.pem

# Import an existing holder key
bun packages/wallet-cli/src/index.ts init \
  --wallet-dir .demo/wallet \
  --holder-key-file ./holder-key.jwk.json
```

## End-To-End Demo Script

```bash
bun scripts/demo-e2e.ts
```

Runs the full flow programmatically: generates trust material, issues a holder-bound credential, imports it, and creates a presentation.

## Example Inputs

Reusable example payloads in `examples/pid/`:

- `pid-minimal.claims.json` - minimal PID-style SD-JWT VC claims
- `pid-full.claims.json` - broader PID-style SD-JWT VC claims
- `pid-basic-request.json` - basic PID DCQL request
- `pid-address-request.json` - address-focused PID DCQL request
- `pid-basic.openid4vp.txt` - by-value `openid4vp://` authorization URL example

## Validate

```bash
bun test
bun run check-types
bun run lint
```

## Notes

- `dc+sd-jwt` format only
- DCQL only, no Presentation Exchange
- `openid4vp://` limited to by-value requests with `client_id`, `nonce`, and `dcql_query`
- wallet trust store for verifiers/readers is out of scope
- issuer certificate artifacts are for external verifier trust bootstrapping; wallet verification uses JWK/JWKS
