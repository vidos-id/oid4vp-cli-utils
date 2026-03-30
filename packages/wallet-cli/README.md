# @vidos-id/wallet-cli

CLI for `dc+sd-jwt` credential holding and OpenID4VP presentation. Wraps the [`@vidos-id/wallet`](../wallet/) library.

It also supports a minimal direct OpenID4VCI receipt flow via credential offers.

For the full issue-hold-present flow, see the [root README](../../).

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

`import` remains a local credential-blob import command only; it does not resolve credential offers.

### `receive`

Receive and store a credential from a minimal OpenID4VCI credential offer.

```bash
# From an openid-credential-offer URI
wallet-cli receive \
  --wallet-dir ./my-wallet \
  --offer 'openid-credential-offer://?credential_offer=...'

# From inline credential-offer JSON
wallet-cli receive \
  --wallet-dir ./my-wallet \
  --offer '{"credential_issuer":"https://issuer.example",...}'
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--offer <value>` (required) - credential offer JSON or `openid-credential-offer://` URI

### `list`

List stored credentials.

```bash
wallet-cli list --wallet-dir ./my-wallet
wallet-cli list --wallet-dir ./my-wallet --vct urn:eudi:pid:1
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
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--credential-id <id>` (required) - credential id (from `list` output)
- `--resolve-status` - fetch and verify the credential status list on demand

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
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--request <value>` (required) - OpenID4VP request JSON or `openid4vp://` URL
- `--credential-id <id>` - use a specific credential (skip selection prompt)
- `--dry-run` - build the response but don't submit it

## Global options

- `--verbose` - enable verbose logging to stderr
- `--version` - show version number
- `--help` - show help for a command

## Notes

- `present` auto-submits `direct_post` and `direct_post.jwt` responses unless `--dry-run` is set
- when multiple credentials match a query, `present` prompts interactively in a TTY or returns an error with a `--credential-id` suggestion in non-TTY environments
- only by-value DCQL requests are supported
- `receive` supports only the minimal OID4VCI subset: by-value offers, pre-authorized-code, JWT proof, and single `dc+sd-jwt` issuance
- credentials are issued with [`@vidos-id/issuer-cli`](../issuer-cli/)
- for remote inputs, use `--request "$(curl -fsSL <raw-url>)"` instead of relying on a local example file

## Test

```bash
bun test packages/wallet-cli/src/index.test.ts
```
