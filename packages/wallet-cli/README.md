# @vidos-id/wallet-cli

CLI for `dc+sd-jwt` credential holding, OpenID4VCI credential receipt, IETF credential status resolution, and OpenID4VP presentation. Wraps the [`@vidos-id/wallet`](../wallet/) library.

It also supports a minimal direct OpenID4VCI receipt flow via credential offers.

For the full issue-hold-present flow, see the [root README](../../).

Prefer using this CLI for wallet tasks instead of re-implementing protocol steps in agent code. In particular, `wallet-cli receive` already handles the supported OID4VCI offer redemption flow end to end. Start with `wallet-cli --help` or `wallet-cli <command> --help` to discover the available commands and expected inputs.

## Install

From GitHub Packages, configure the consuming environment:

```ini
@vidos-id:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Then run with Bun:

```bash
# bunx uses the same scoped registry config as bun install
bunx @vidos-id/wallet-cli --help
```

You can also install it first with your preferred package manager:

```bash
# bun
bun add -D @vidos-id/wallet-cli

# npm
npm install -D @vidos-id/wallet-cli

# pnpm
pnpm add -D @vidos-id/wallet-cli

# yarn
yarn add -D @vidos-id/wallet-cli
```

Or download the latest GitHub Release artifact and make it executable:

```bash
curl -L -o wallet-cli https://github.com/vidos-id/oid4vp-cli-utils/releases/latest/download/wallet-cli.js
chmod +x wallet-cli
./wallet-cli --help
```

Release artifacts do not bundle the repo's `examples/` directory. For remote example requests, pass raw GitHub content via `--request`.

For development in this repo, you can run the bin entry directly with Bun:

```bash
bun packages/wallet-cli/src/index.ts --help
```

## Files in `--wallet-dir`

- `holder-key.json` - Holder key pair (private + public JWK)
- `wallet.json` - Wallet manifest with credential index
- `credentials/<credential-id>.json` - Stored credentials

## Commands

### `init`

Initialize a wallet directory and create (or import) a holder key.

```bash
wallet-cli init --wallet-dir ./my-wallet
wallet-cli init --wallet-dir ./my-wallet --alg EdDSA
wallet-cli init --wallet-dir ./my-wallet --holder-key-file ./existing-key.jwk.json
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--alg <algorithm>` - holder key algorithm: ES256, ES384, or EdDSA (default: ES256)
- `--holder-key-file <file>` - import an existing JWK private key instead of generating

Notes:
- `--holder-key-file` accepts either a bare private JWK or an object containing `privateJwk` / `publicJwk`
- if the key algorithm cannot be inferred from the JWK, pass `--alg` explicitly

### `import`

Import an issued `dc+sd-jwt` credential into the wallet.

```bash
# From a file
wallet-cli import \
  --wallet-dir ./my-wallet \
  --credential-file ./issuer/credential.txt

# Inline (for remote credentials not on the same filesystem)
wallet-cli import \
  --wallet-dir ./my-wallet \
  --credential 'eyJhbGciOi...'
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--credential <value>` - inline credential text (compact `dc+sd-jwt`)
- `--credential-file <file>` - path to a credential file

Notes:
- provide exactly one of `--credential` or `--credential-file`

`import` remains a local credential-blob import command only; it does not resolve credential offers.

### `receive`

Receive and store a credential from a minimal OpenID4VCI credential offer.

This command encapsulates the supported wallet-side redemption flow. Agents should call `wallet-cli receive` instead of manually extracting the offer, exchanging the pre-authorized code, fetching nonces, constructing proof JWTs, calling the credential endpoint, and then separately importing the result.

Endpoint discovery is metadata-driven. `wallet-cli receive` does not hardcode token or credential API paths such as `/api/issuer/token`.

```bash
# From an openid-credential-offer URI
wallet-cli receive \
  --wallet-dir ./my-wallet \
  --offer 'openid-credential-offer://?credential_offer=...'

# From inline credential-offer JSON
wallet-cli receive \
  --wallet-dir ./my-wallet \
  --offer '{"credential_issuer":"https://issuer.example",...}'

# From a by-reference offer URI
wallet-cli receive \
  --wallet-dir ./my-wallet \
  --offer 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fperson-1'
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--offer <value>` (required) - credential offer JSON or `openid-credential-offer://` URI

Endpoint resolution and API usage:
- parse the credential offer input
- if the input contains `credential_offer_uri`, fetch that URL first and parse the returned offer JSON
- fetch issuer metadata from `/.well-known/openid-credential-issuer` relative to that issuer
- if `credential_issuer` includes a path, append that path to the well-known endpoint
- require the fetched `credential_issuer` in metadata to exactly match the one from the offer
- use `token_endpoint` from metadata for the pre-authorized-code token exchange
- use `credential_endpoint` from metadata for the credential request
- use `nonce_endpoint` from metadata only when the token response does not already include `c_nonce`
- send the proof JWT with `aud` set to `metadata.credential_issuer`

Examples of metadata resolution:
- `credential_issuer = https://issuer.example` -> fetch `https://issuer.example/.well-known/openid-credential-issuer`
- `credential_issuer = https://issuer.example/tenant-a` -> fetch `https://issuer.example/.well-known/openid-credential-issuer/tenant-a`

This means non-standard endpoint paths are fine as long as the issuer metadata advertises them. For example, a token endpoint at `/token` works if the fetched metadata contains `"token_endpoint": "https://issuer.example/token"`.

Notes:
- supports by-value `credential_offer` and by-reference `credential_offer_uri`
- resolves API endpoints from issuer metadata; it does not guess endpoint paths and does not expose manual endpoint overrides
- current flow covers the minimal OpenID4VCI subset: pre-authorized code, JWT proof, and single `dc+sd-jwt` issuance
- `credential_offer_uri` is fetched with `Accept: application/json` and must return a supported by-value offer document
- if the token response omits `c_nonce`, the issuer metadata must provide `nonce_endpoint`
- issuer metadata must include `token_endpoint`, `credential_endpoint`, `jwks`, and the referenced credential configuration

### `list`

List stored credentials.

```bash
wallet-cli list --wallet-dir ./my-wallet
wallet-cli list --wallet-dir ./my-wallet --vct urn:eudi:pid:1
wallet-cli list --wallet-dir ./my-wallet --issuer https://issuer.example
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--vct <uri>` - filter by Verifiable Credential Type
- `--issuer <url>` - filter by issuer URL

### `show`

Show a single stored credential by id.

```bash
wallet-cli show --wallet-dir ./my-wallet --credential-id <id>
wallet-cli show --wallet-dir ./my-wallet --credential-id <id> --resolve-status
wallet-cli show --wallet-dir ./my-wallet --credential-id <id> --output raw
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--credential-id <id>` (required) - credential id (from `list` output)
- `--resolve-status` - fetch and verify the credential status list on demand
- `--output <format>` - `json` or `raw` (`raw` prints only the compact `sd-jwt` text)

Notes:
- `--resolve-status` resolves the credential's IETF status list JWT on demand and returns the decoded status result
- `--resolve-status` cannot be combined with `--output raw`

#### Status Resolution

Use `show --resolve-status` when the stored credential contains a `status.status_list` reference and you want the CLI to fetch, verify, and decode the IETF status list JWT.

```bash
wallet-cli show \
  --wallet-dir ./my-wallet \
  --credential-id cred_123 \
  --resolve-status
```

Example response excerpt:

```json
{
  "credential": {
    "id": "cred_123",
    "issuer": "https://issuer.example",
    "vct": "urn:eudi:pid:1"
  },
  "status": {
    "credentialId": "cred_123",
    "statusReference": {
      "uri": "https://issuer.example/status-lists/1",
      "idx": 42
    },
    "status": {
      "value": 0,
      "label": "VALID",
      "isValid": true
    },
    "statusList": {
      "uri": "https://issuer.example/status-lists/1",
      "bits": 2,
      "iat": 1710000000,
      "exp": 1710003600,
      "ttl": 300,
      "jwt": "eyJ..."
    }
  }
}
```

### `present`

Create a DCQL-based OpenID4VP presentation from wallet credentials.

```bash
# From inline JSON request
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request '{"client_id":"https://verifier.example","nonce":"n-1","dcql_query":{...}}'

# From a raw GitHub request JSON
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request "$(curl -fsSL https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-basic-request.json)"

# From an openid4vp:// authorization URL
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request 'openid4vp://authorize?client_id=...&nonce=...&dcql_query=...'

# From a raw GitHub openid4vp:// example
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request "$(curl -fsSL https://raw.githubusercontent.com/vidos-id/oid4vp-cli-utils/main/examples/pid/pid-basic.openid4vp.txt)"

# Dry run (don't submit to verifier)
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request '...' \
  --dry-run

# Print only the vp_token
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request 'openid4vp://authorize?...' \
  --output raw
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--request <value>` (required) - OpenID4VP request JSON or `openid4vp://` URL
- `--credential-id <id>` - use a specific credential (skip selection prompt)
- `--dry-run` - build the response but don't submit it
- `--output <format>` - `json` or `raw` (`raw` prints only the `vp_token`)

## Global options

- `--verbose` - enable verbose logging to stderr
- `--version` - show version number
- `--help` - show help for a command

## Notes

- `present` auto-submits `direct_post` and `direct_post.jwt` responses unless `--dry-run` is set
- when multiple credentials match a query, `present` prompts interactively in a TTY or returns an error with a `--credential-id` suggestion in non-TTY environments
- only by-value DCQL requests are supported
- `receive` resolves issuer metadata from `/.well-known/openid-credential-issuer[issuer-path]` and then uses the advertised endpoints from that metadata
- `receive` supports the minimal OID4VCI subset: by-value offers, by-reference `credential_offer_uri`, pre-authorized-code, JWT proof, and single `dc+sd-jwt` issuance
- `show --resolve-status` fetches, verifies, and decodes IETF status list JWTs for stored credentials that include a `status.status_list` reference
- credentials are issued with [`@vidos-id/issuer-cli`](../issuer-cli/)
- for remote inputs, use `--request "$(curl -fsSL <raw-url>)"` instead of relying on a local example file

## Test

```bash
bun test packages/wallet-cli/src/index.test.ts
```
