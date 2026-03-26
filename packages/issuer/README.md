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
- token exchange + nonce issuance
- proof JWT validation with `typ=openid4vci-proof+jwt`
- claim-set driven issuance
- issuer key and certificate generation for demo trust bootstrapping
- multi-algorithm support: ES256, ES384, EdDSA

## Specs

- SD-JWT VC: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-15
- OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OpenID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

This package implements a deliberately small internal/demo subset of those specs.

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
});
```

For holder binding, the wallet provides its public JWK via a proof JWT -- see the [`@vidos-id/wallet`](../wallet/) library and [`scripts/demo-e2e.ts`](../../scripts/demo-e2e.ts) for the full flow.

## Test

```bash
bun test packages/issuer/src/issuer.test.ts
```
