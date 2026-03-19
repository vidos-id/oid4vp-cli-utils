# wallet

Minimal demo wallet library for importing, storing, and presenting `dc+sd-jwt` credentials.

## Features

- holder-key generation
- pluggable storage interface
- issuer JWK/JWKS credential verification
- DCQL matching with `dcql`
- `oid4vp://` authorization URL parsing for by-value DCQL requests
- selective disclosure presentation building
- KB-JWT holder binding

## Example

```ts
import { InMemoryWalletStorage, Wallet } from "wallet";

const wallet = new Wallet(new InMemoryWalletStorage());

await wallet.getOrCreateHolderKey();

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

const requestFromUrl = Wallet.parseAuthorizationRequestUrl(
  "oid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&nonce=nonce-123&response_type=vp_token&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22person%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22https%3A%2F%2Fexample.com%2FPersonCredential%22%5D%7D%7D%5D%7D",
);
```

Supported `oid4vp://` subset:
- by-value only
- requires `client_id`, `nonce`, and `dcql_query`
- rejects `request`, `request_uri`, `scope`, and Presentation Exchange input

## Test

```bash
bun test packages/wallet/src/wallet.test.ts
```
