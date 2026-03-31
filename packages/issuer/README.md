# @vidos-id/issuer

Minimal demo issuer library for holder-bound `dc+sd-jwt` credentials.

For the CLI wrapper, see [`@vidos-id/issuer-cli`](../issuer-cli/). For the installed CLI flow, see the [root README](../../). For development, the CLI bin can be run with `bun packages/issuer-cli/src/index.ts`.

## Install

Configure GitHub Packages in the consuming repo:

```ini
@vidos-id:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

Install with your preferred package manager:

```bash
# bun
bun add @vidos-id/issuer

# npm
npm install @vidos-id/issuer

# pnpm
pnpm add @vidos-id/issuer

# yarn
yarn add @vidos-id/issuer
```

This package is currently published as raw TypeScript and is intended for Bun-based consumers.

## Features

- issuer metadata + JWKS output
- pre-authorized grant + credential offer creation
- `openid-credential-offer://` serialization helpers for both `credential_offer` and `credential_offer_uri`
- token exchange + nonce issuance
- proof JWT validation with `typ=openid4vci-proof+jwt`
- claim-set driven issuance
- token status list creation, signing, and status updates
- issuer key and certificate generation for demo trust bootstrapping
- multi-algorithm support: ES256, ES384, EdDSA

## Specs

- SD-JWT VC: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-15
- OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OpenID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

This package implements a deliberately small internal/demo subset of those specs.

Supported OID4VCI subset:

- by-value credential offers and by-reference `credential_offer_uri`
- pre-authorized-code flow only
- single `dc+sd-jwt` issuance only
- storage-agnostic request/response helpers for embedding in your own server

Out of scope:

- authorization-code flow
- DPoP
- wallet attestation / key attestation
- `tx_code`, deferred issuance, encrypted responses, batch issuance

## Example

```ts
import { createIssuer, generateIssuerTrustMaterial } from "@vidos-id/issuer";

const trust = await generateIssuerTrustMaterial({ alg: "ES256" });

const issuer = createIssuer({
  issuer: "https://issuer.example",
  signingKey: {
    alg: trust.alg,
    privateJwk: trust.privateJwk,
    publicJwk: trust.publicJwk,
  },
  credentialConfigurationsSupported: {
    person: {
      format: "dc+sd-jwt",
      vct: "https://example.com/PersonCredential",
    },
  },
});

const offer = issuer.createCredentialOffer({
  credential_configuration_id: "person",
  claims: { given_name: "Ada", family_name: "Lovelace" },
});

const offerUri = issuer.createCredentialOfferUri({
  credential_configuration_id: "person",
  claims: { given_name: "Ada", family_name: "Lovelace" },
});

const offerReferenceUri = issuer.createCredentialOfferReferenceUri(
  "https://issuer.example/offers/person-1"
);

const statusList = issuer.createStatusList({
  uri: "https://issuer.example/status-lists/1",
  bits: 2,
  ttl: 300,
});

const allocatedStatus = issuer.allocateCredentialStatus({ statusList });

await db.saveGrant(offer.preAuthorizedGrant.preAuthorizedCode, offer.preAuthorizedGrant);

const token = issuer.exchangePreAuthorizedCode({
  tokenRequest: {
    grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": offer.preAuthorizedGrant.preAuthorizedCode,
  },
  preAuthorizedGrant: await db.readGrant(offer.preAuthorizedGrant.preAuthorizedCode),
});

await db.saveAccessToken(token.accessTokenRecord.accessToken, token.accessTokenRecord);

const issued = await issuer.issueCredential({
  accessToken: await db.readAccessToken(token.accessTokenRecord.accessToken),
  credential_configuration_id: "person",
  status: allocatedStatus.credentialStatus,
});

const statusListJwt = await issuer.createStatusListToken(allocatedStatus.updatedStatusList);
```

For holder binding, the wallet provides its public JWK via a proof JWT -- see the [`@vidos-id/wallet`](../wallet/) library and [`scripts/demo-e2e.ts`](../../scripts/demo-e2e.ts) for the full flow.

Host applications own HTTP routing and persistence. The issuer helpers return updated grant, access-token, and nonce records so your server can store them however it wants.

Credential offer delivery options:

- `issuer.createCredentialOffer(...)` returns the offer JSON document that you can embed directly or serve from your own endpoint
- `issuer.createCredentialOfferUri(...)` wraps that JSON by value in `openid-credential-offer://?credential_offer=...`
- `issuer.createCredentialOfferReferenceUri("https://issuer.example/offers/person-1")` creates `openid-credential-offer://?credential_offer_uri=...`
- when using `credential_offer_uri`, your application is responsible for hosting the offer JSON at that URL

## Test

```bash
bun test packages/issuer/src/issuer.test.ts
```
