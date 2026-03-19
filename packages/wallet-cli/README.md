# wallet-cli

Demo CLI for the `wallet` package with filesystem-backed storage.

## Commands

- `import`
- `list`
- `show`
- `present`

Storage layout:
- `holder-key.json`
- `wallet.json`
- `credentials/<credential-id>.json`

## Example

Import a credential:

```bash
bun packages/wallet-cli/src/index.ts import \
  --wallet-dir .demo/wallet \
  --credential-file .demo/credential.txt \
  --issuer https://issuer.example \
  --issuer-jwks-file .demo/jwks.json
```

Present a credential:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request-file .demo/request.json
```

Present from an `oid4vp://` URL:

```bash
bun packages/wallet-cli/src/index.ts present \
  --wallet-dir .demo/wallet \
  --request-file examples/pid/pid-basic.oid4vp.txt
```

Notes:
- `present` accepts JSON request input or an `oid4vp://` authorization URL
- only by-value DCQL requests are supported
- when multiple credentials match and `--credential-id` is omitted, the CLI prompts interactively to choose one
- in non-TTY mode, ambiguous matches fail instead of guessing

## Test

```bash
bun test packages/wallet-cli/src/index.test.ts
```
