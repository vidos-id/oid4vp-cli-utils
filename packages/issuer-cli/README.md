# issuer-cli

Demo CLI for the `issuer` package.

## Commands

- `metadata`
- `create-offer`
- `create-grant`
- `nonce`
- `issue`
- `generate-trust-material`

## Example

Generate trust material:

```bash
bun packages/issuer-cli/src/index.ts generate-trust-material \
  --trust-artifact-out .demo/trust.json \
  --jwks-out .demo/jwks.json
```

Issue a credential:

```bash
bun packages/issuer-cli/src/index.ts issue \
  --issuer https://issuer.example \
  --signing-key-file .demo/trust.json \
  --vct https://example.com/PersonCredential \
  --claims '{"given_name":"Ada"}' \
  --proof-file .demo/proof.jwt
```

## Test

```bash
bun test packages/issuer-cli/src/index.test.ts
```
