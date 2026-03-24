# oid4vp-cli-utils

CLI tools for quick `dc+sd-jwt` credential issuance, holding, and OpenID4VP presentation.

Built for simple, scriptable credential flows -- primarily created as a PoC for making wallet operations CLI-consumable so they can be driven by AI agents like [OpenClaw](https://openclaw.ai/) 🦞.

## Packages

| Package | Description |
|---------|-------------|
| [`issuer-cli`](packages/issuer-cli/) | Issue credentials and manage issuer key material |
| [`wallet-cli`](packages/wallet-cli/) | Hold credentials and create OpenID4VP presentations |
| [`issuer`](packages/issuer/) | Issuer library (used by issuer-cli) |
| [`wallet`](packages/wallet/) | Wallet library (used by wallet-cli) |

## Install

Release artifacts are published on GitHub Releases as Bun-executable single-file CLIs.

Requirements:

- [Bun](https://bun.sh/) installed

Download the latest release assets:

```bash
# wallet-cli
curl -L -o wallet-cli https://github.com/vidos-id/oid4vp-cli-utils/releases/latest/download/wallet-cli.js
chmod +x wallet-cli

# issuer-cli
curl -L -o issuer-cli https://github.com/vidos-id/oid4vp-cli-utils/releases/latest/download/issuer-cli.js
chmod +x issuer-cli
```

Run them directly:

```bash
./wallet-cli --help
./issuer-cli --help
```

Optional: install globally on your machine by moving them onto your `PATH`:

```bash
mv wallet-cli ~/.local/bin/wallet-cli
mv issuer-cli ~/.local/bin/issuer-cli
```

These artifacts are built for Bun, so they are not directly consumable via `npx` and are not currently published as npm packages for `bunx`.

For development in this repo, you can run the package bin entry directly with Bun:

```bash
bun packages/wallet-cli/src/index.ts --help
bun packages/issuer-cli/src/index.ts --help
```

## Quick Start

The full issue-hold-present flow in 4 commands:

```bash
# 1. Initialize wallet (creates holder key)
./wallet-cli init \
  --wallet-dir .demo/wallet

# 2. Initialize issuer (generates signing key, JWKS, trust material)
./issuer-cli init \
  --issuer-dir .demo/issuer

# 3. Issue a holder-bound credential
./issuer-cli issue \
  --issuer-dir .demo/issuer \
  --holder-key-file .demo/wallet/holder-key.json \
  --issuer https://issuer.example \
  --vct urn:eudi:pid:1 \
  --credential-file credential.txt \
  --claims-file examples/pid/pid-minimal.claims.json

# 4. Import credential into the wallet
./wallet-cli import \
  --wallet-dir .demo/wallet \
  --credential-file .demo/issuer/credential.txt
```

Then present it:

```bash
./wallet-cli present \
  --wallet-dir .demo/wallet \
  --request '{"client_id":"https://verifier.example","nonce":"n-1","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}}'
```

Or from an `openid4vp://` authorization URL:

```bash
./wallet-cli present \
  --wallet-dir .demo/wallet \
  --request 'openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&nonce=n-1&response_type=vp_token&dcql_query=...'
```

See [`issuer-cli`](packages/issuer-cli/) and [`wallet-cli`](packages/wallet-cli/) for full command reference.

## Algorithms

Supports ES256, ES384, and EdDSA throughout. Both CLIs accept `--alg` to choose:

```bash
# Issuer with ES256
./issuer-cli init --issuer-dir .demo/issuer --alg ES256

# Wallet with EdDSA
./wallet-cli init --wallet-dir .demo/wallet --alg EdDSA
```

Defaults: EdDSA for issuer signing, ES256 for wallet holder keys.

You can also import existing key material instead of generating:

```bash
# Import a PEM or JWK private key (algorithm auto-detected)
./issuer-cli import-trust-material \
  --issuer-dir .demo/issuer \
  --private-key ./private-key.pem

# Import an existing holder key
./wallet-cli init \
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
