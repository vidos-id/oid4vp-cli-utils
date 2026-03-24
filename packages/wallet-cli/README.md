# wallet-cli

CLI for `dc+sd-jwt` credential holding and OpenID4VP presentation. Wraps the [`wallet`](../wallet/) library.

For the full issue-hold-present flow, see the [root README](../../).

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
```

Options:
- `--wallet-dir <dir>` (required) - path to the wallet directory
- `--credential-id <id>` (required) - credential id (from `list` output)

### `present`

Create a DCQL-based OpenID4VP presentation from wallet credentials.

```bash
# From inline JSON request
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request '{"client_id":"https://verifier.example","nonce":"n-1","dcql_query":{...}}'

# From an openid4vp:// authorization URL
wallet-cli present \
  --wallet-dir ./my-wallet \
  --request 'openid4vp://authorize?client_id=...&nonce=...&dcql_query=...'

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
- credentials are issued with [`issuer-cli`](../issuer-cli/)

## Test

```bash
bun test packages/wallet-cli/src/index.test.ts
```
