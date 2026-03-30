# @vidos-id/wallet

Minimal demo wallet library for importing, storing, and presenting `dc+sd-jwt` credentials.

For the CLI wrapper, see [`@vidos-id/wallet-cli`](../wallet-cli/). For the installed CLI flow, see the [root README](../../). For development, the CLI bin can be run with `bun packages/wallet-cli/src/index.ts`.

## Install

Configure GitHub Packages in the consuming repo:

```ini
@vidos-id:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Install with your preferred package manager:

```bash
# bun
bun add @vidos-id/wallet

# npm
npm install @vidos-id/wallet

# pnpm
pnpm add @vidos-id/wallet

# yarn
yarn add @vidos-id/wallet
```

This package is currently published as raw TypeScript and is intended for Bun-based consumers.

## Features

- holder-key generation (ES256, ES384, EdDSA)
- holder-key import from JWK
- pluggable storage interface
- issuer JWK/JWKS credential verification (optional)
- direct OID4VCI receipt from credential offers
- on-demand credential status resolution via Token Status List JWTs
- DCQL matching with `dcql`
- `openid4vp://` authorization URL parsing for by-value DCQL requests
- selective disclosure presentation building
- KB-JWT holder binding
- `direct_post` and `direct_post.jwt` authorization response submission

## Example

```ts
import {
  InMemoryWalletStorage,
  Wallet,
  receiveCredentialFromOffer,
} from "@vidos-id/wallet";

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

// Receive directly from a minimal OID4VCI credential offer
await receiveCredentialFromOffer(
  wallet,
  'openid-credential-offer://?credential_offer=...'
);

// Resolve credential status only when needed
const status = await wallet.getCredentialStatus("credential-id");

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

Supported OID4VCI subset:
- by-value credential offers only
- pre-authorized-code flow only
- JWT proof only
- single `dc+sd-jwt` credential request + import

## See also

- [`@vidos-id/issuer`](../issuer/) - issuer library for credential issuance
- [`scripts/demo-e2e.ts`](../../scripts/demo-e2e.ts) - full programmatic flow using both libraries

## Test

```bash
bun test packages/wallet/src/wallet.test.ts
```
