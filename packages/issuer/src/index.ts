export { generateIssuerTrustMaterial } from "./crypto.ts";
export { IssuerError } from "./errors.ts";
export { createIssuer, DemoIssuer } from "./issuer.ts";
export {
	type ClaimSet,
	type CreateCredentialOfferInput,
	type CreatePreAuthorizedGrantInput,
	type CredentialConfiguration,
	type CredentialRequest,
	claimSetSchema,
	createCredentialOfferInputSchema,
	createPreAuthorizedGrantInputSchema,
	credentialConfigurationSchema,
	credentialRequestSchema,
	type IssuerConfigInput,
	issuerConfigSchema,
	type Jwk,
	jwkSchema,
	proofObjectSchema,
	type TokenRequest,
	tokenRequestSchema,
} from "./schemas.ts";
