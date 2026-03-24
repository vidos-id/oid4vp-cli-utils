# issuer-cli

CLI for `dc+sd-jwt` credential issuance. Wraps the [`issuer`](../issuer/) library.

For the full issue-hold-present flow, see the [root README](../../).

## Files in `--issuer-dir`

- `signing-key.json` - Issuer signing key (algorithm, private + public JWK)
- `jwks.json` - Public JWKS for verifiers and wallets
- `trust.json` - Verifier-facing trust artifact (certificate chain + JWK)
- `credential-*.txt` - Issued credentials

## Commands

### `init`

Initialize an issuer directory with signing key, JWKS, and trust material.

```bash
issuer-cli init --issuer-dir ./my-issuer
issuer-cli init --issuer-dir ./my-issuer --alg ES256
```

Options:
- `--issuer-dir <dir>` (required) - path to the issuer directory
- `--alg <algorithm>` - signing algorithm: ES256, ES384, or EdDSA (default: EdDSA)

### `issue`

Issue a `dc+sd-jwt` credential.

```bash
issuer-cli issue \
  --issuer-dir ./my-issuer \
  --issuer https://issuer.example \
  --vct urn:eudi:pid:1 \
  --claims-file claims.json

# With holder binding (from wallet-cli holder key file)
issuer-cli issue \
  --issuer-dir ./my-issuer \
  --issuer https://issuer.example \
  --vct urn:eudi:pid:1 \
  --claims-file claims.json \
  --holder-key-file ./wallet/holder-key.json

# With holder binding (inline JWK, for remote wallets)
issuer-cli issue \
  --issuer-dir ./my-issuer \
  --issuer https://issuer.example \
  --vct urn:eudi:pid:1 \
  --claims '{"given_name":"Ada"}' \
  --holder-key '{"kty":"EC","crv":"P-256","x":"...","y":"..."}'
```

Options:
- `--issuer-dir <dir>` (required) - path to issuer directory with `signing-key.json`
- `--issuer <url>` (required) - issuer identifier URL
- `--vct <uri>` (required) - Verifiable Credential Type URI
- `--claims <json>` - inline JSON claims
- `--claims-file <file>` - path to JSON claims file
- `--holder-key-file <file>` - wallet holder key file for holder binding (omit for unbound)
- `--holder-key <json>` - inline holder key JWK JSON (alternative to `--holder-key-file`)
- `--credential-file <name>` - output filename (default: `credential-<uuid>.txt`)
- `--signing-key-file <file>` - override the signing key from `--issuer-dir`

### `generate-trust-material`

Generate key material, JWKS, and self-signed certificate artifacts. Useful when you need individual output files instead of the `--issuer-dir` layout.

```bash
issuer-cli generate-trust-material --issuer-dir ./my-issuer
issuer-cli generate-trust-material --issuer-dir ./my-issuer --alg ES384
```

Options:
- `--issuer-dir <dir>` - write default output files to this directory
- `--alg <algorithm>` - signing algorithm: ES256, ES384, or EdDSA (default: EdDSA)
- `--kid <kid>` - key id (default: `issuer-key-1`)

### `import-trust-material`

Import an existing private key (PEM or JWK) and produce issuer artifacts. The algorithm is auto-detected from the key type (EC/P-256 = ES256, EC/P-384 = ES384, OKP = EdDSA).

```bash
# Import PEM private key (generates self-signed certificate)
issuer-cli import-trust-material \
  --issuer-dir ./my-issuer \
  --private-key ./private-key.pem

# Import JWK with existing certificate
issuer-cli import-trust-material \
  --issuer-dir ./my-issuer \
  --private-key ./private-key.json \
  --certificate ./cert.pem

# Override auto-detected algorithm
issuer-cli import-trust-material \
  --issuer-dir ./my-issuer \
  --private-key ./key.pem \
  --alg ES256
```

Options:
- `--issuer-dir <dir>` (required) - output directory
- `--private-key <file>` (required) - PEM (PKCS#8) or JWK JSON private key
- `--certificate <file>` - PEM certificate (if omitted, self-signed is generated)
- `--alg <algorithm>` - override algorithm detection

## Global options

- `--verbose` - enable verbose logging to stderr
- `--version` - show version number
- `--help` - show help for a command

## Notes

- `issue` writes to `--issuer-dir` and fails if the credential file already exists
- without `--holder-key-file` or `--holder-key`, issuance is unbound (no `cnf` claim)
- reserved protocol claims (`vct`, `iss`) are issuer-controlled
- credential output goes to `--issuer-dir`; use [`wallet-cli import`](../wallet-cli/) to bring it into a wallet

## Test

```bash
bun test packages/issuer-cli/src/index.test.ts
```
