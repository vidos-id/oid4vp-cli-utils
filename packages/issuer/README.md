# issuer

Minimal demo issuer library for holder-bound `dc+sd-jwt` credentials.

## Features

- issuer metadata + JWKS output
- pre-authorized grant + credential offer creation
- token exchange + nonce issuance
- proof JWT validation with `typ=openid4vci-proof+jwt`
- claim-set driven issuance
- issuer key and certificate generation for demo trust bootstrapping

## Specs

- SD-JWT VC: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-15
- OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OpenID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

This package implements a deliberately small internal/demo subset of those specs.

## Example

```ts
import { createIssuer, generateIssuerTrustMaterial } from "issuer";

const trust = await generateIssuerTrustMaterial();

const issuer = createIssuer({
  issuer: "https://issuer.example",
  signingKey: {
    alg: "EdDSA",
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
```

## Test

```bash
bun test packages/issuer/src/issuer.test.ts
```
