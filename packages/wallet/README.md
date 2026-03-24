# wallet

Minimal demo wallet library for importing, storing, and presenting `dc+sd-jwt` credentials.

For the CLI wrapper, see [`wallet-cli`](../wallet-cli/). For the full issue-hold-present flow, see the [root README](../../).

## Features

- holder-key generation (ES256, ES384, EdDSA)
- holder-key import from JWK
- pluggable storage interface
- issuer JWK/JWKS credential verification (optional)
- DCQL matching with `dcql`
- `openid4vp://` authorization URL parsing for by-value DCQL requests
- selective disclosure presentation building
- KB-JWT holder binding
- `direct_post` and `direct_post.jwt` authorization response submission

## Example

```ts
import { InMemoryWalletStorage, Wallet } from "wallet";

const wallet = new Wallet(new InMemoryWalletStorage());

// Default holder key algorithm is ES256; pass "ES384" or "EdDSA" for alternatives
await wallet.getOrCreateHolderKey("ES256");

// Import a credential (after issuing with the issuer library)
await wallet.importCredential({
  credential: "eyJ...",
});

// Optionally verify against issuer JWKS on import
await wallet.importCredential({
  credential: "eyJ...",
  issuer: { issuer: "https://issuer.example", jwks: { keys: [/* ... */] } },
});

// Create a presentation from a DCQL request
const presentation = await wallet.createPresentation({
  client_id: "https://verifier.example",
  nonce: "nonce-123",
  dcql_query: {
    credentials: [
      {
        id: "person",
        format: "dc+sd-jwt",
        meta: { vct_values: ["https://example.com/PersonCredential"] },
      },
    ],
  },
});

// Parse an openid4vp:// authorization URL
const request = Wallet.parseAuthorizationRequestUrl("openid4vp://authorize?...");
```

Supported `openid4vp://` subset:
- by-value only
- requires `client_id`, `nonce`, and `dcql_query`
- rejects `request`, `request_uri`, `scope`, and Presentation Exchange input

## See also

- [`issuer`](../issuer/) - issuer library for credential issuance
- [`scripts/demo-e2e.ts`](../../scripts/demo-e2e.ts) - full programmatic flow using both libraries

## Test

```bash
bun test packages/wallet/src/wallet.test.ts
```
