import { z } from "zod";

export const jwkSchema = z
	.object({
		kty: z.string().min(1),
		kid: z.string().min(1).optional(),
		alg: z.string().min(1).optional(),
		crv: z.string().min(1).optional(),
		x: z.string().min(1).optional(),
		y: z.string().min(1).optional(),
		d: z.string().min(1).optional(),
		n: z.string().min(1).optional(),
		e: z.string().min(1).optional(),
		use: z.string().min(1).optional(),
		key_ops: z.array(z.string().min(1)).optional(),
		x5c: z.array(z.string().min(1)).optional(),
	})
	.catchall(z.unknown());

export const claimSetSchema = z.record(z.string(), z.unknown());

export const credentialConfigurationSchema = z.object({
	format: z.literal("dc+sd-jwt"),
	vct: z.string().min(1),
	scope: z.string().min(1).optional(),
	claims: z.record(z.string(), z.unknown()).optional(),
	proof_signing_alg_values_supported: z
		.array(z.string().min(1))
		.default(["ES256", "ES384", "EdDSA"]),
});

export const signingAlgSchema = z.enum(["ES256", "ES384", "EdDSA"]);
export type SigningAlg = z.infer<typeof signingAlgSchema>;

export const statusListBitsSchema = z.union([
	z.literal(1),
	z.literal(2),
	z.literal(4),
	z.literal(8),
]);

export const tokenStatusValueSchema = z.number().int().min(0).max(255);

export const credentialStatusListReferenceSchema = z.object({
	idx: z.number().int().nonnegative(),
	uri: z.string().min(1),
});

export const credentialStatusSchema = z.object({
	status_list: credentialStatusListReferenceSchema,
});

export const statusListRecordSchema = z.object({
	uri: z.string().min(1),
	bits: statusListBitsSchema.default(1),
	statuses: z.array(tokenStatusValueSchema).default([]),
	ttl: z.number().int().positive().optional(),
	expiresAt: z.number().int().positive().optional(),
	aggregation_uri: z.string().min(1).optional(),
});

export const createStatusListInputSchema = statusListRecordSchema.omit({
	statuses: true,
});

export const allocateCredentialStatusInputSchema = z.object({
	statusList: statusListRecordSchema,
	status: tokenStatusValueSchema.default(0),
});

export const updateCredentialStatusInputSchema = z.object({
	statusList: statusListRecordSchema,
	idx: z.number().int().nonnegative(),
	status: tokenStatusValueSchema,
});

export const issuerConfigSchema = z.object({
	issuer: z.string().url(),
	credentialConfigurationsSupported: z
		.record(z.string(), credentialConfigurationSchema)
		.refine(
			(value) => Object.keys(value).length > 0,
			"At least one credential configuration is required",
		),
	signingKey: z.object({
		alg: signingAlgSchema.default("EdDSA"),
		privateJwk: jwkSchema,
		publicJwk: jwkSchema,
	}),
	endpoints: z
		.object({
			token: z.string().url().optional(),
			credential: z.string().url().optional(),
			nonce: z.string().url().optional(),
		})
		.optional(),
	nonceTtlSeconds: z.number().int().positive().default(300),
	grantTtlSeconds: z.number().int().positive().default(600),
	tokenTtlSeconds: z.number().int().positive().default(600),
});

export const createPreAuthorizedGrantInputSchema = z.object({
	credential_configuration_id: z.string().min(1),
	claims: claimSetSchema,
	expires_in: z.number().int().positive().optional(),
});

export const createCredentialOfferInputSchema =
	createPreAuthorizedGrantInputSchema;

export const preAuthorizedGrantTypeSchema = z.literal(
	"urn:ietf:params:oauth:grant-type:pre-authorized_code",
);

export const credentialOfferGrantSchema = z.object({
	"pre-authorized_code": z.string().min(1),
	tx_code: z.never().optional(),
});

export const credentialOfferSchema = z.object({
	credential_issuer: z.string().url(),
	credential_configuration_ids: z.array(z.string().min(1)).min(1).max(1),
	grants: z.object({
		"urn:ietf:params:oauth:grant-type:pre-authorized_code":
			credentialOfferGrantSchema,
	}),
});

export const credentialOfferUriSchema = z
	.string()
	.min(1)
	.refine((value) => {
		try {
			return new URL(value).protocol === "openid-credential-offer:";
		} catch {
			return false;
		}
	}, "Credential offer URI must use openid-credential-offer://");

export const issuerMetadataCredentialConfigurationSchema = z.object({
	format: z.literal("dc+sd-jwt"),
	vct: z.string().min(1),
	scope: z.string().min(1),
	proof_types_supported: z.object({
		jwt: z.object({
			proof_signing_alg_values_supported: z.array(z.string().min(1)).min(1),
		}),
	}),
	cryptographic_binding_methods_supported: z.array(z.literal("jwk")).min(1),
	credential_signing_alg_values_supported: z.array(z.string().min(1)).min(1),
});

export const issuerMetadataSchema = z.object({
	credential_issuer: z.string().url(),
	token_endpoint: z.string().url(),
	credential_endpoint: z.string().url(),
	nonce_endpoint: z.string().url().optional(),
	jwks: z.object({
		keys: z.array(jwkSchema).min(1),
	}),
	credential_configurations_supported: z.record(
		z.string(),
		issuerMetadataCredentialConfigurationSchema,
	),
});

export const preAuthorizedGrantRecordSchema = z.object({
	preAuthorizedCode: z.string().min(1),
	credentialConfigurationId: z.string().min(1),
	claims: claimSetSchema,
	expiresAt: z.number().int(),
	used: z.boolean(),
});

export const tokenRequestSchema = z.object({
	grant_type: preAuthorizedGrantTypeSchema,
	"pre-authorized_code": z.string().min(1),
	tx_code: z.string().min(1).optional(),
});

export const tokenResponseSchema = z.object({
	access_token: z.string().min(1),
	token_type: z.literal("Bearer"),
	expires_in: z.number().int().positive(),
	credential_configuration_id: z.string().min(1),
	c_nonce: z.string().min(1).optional(),
	c_nonce_expires_in: z.number().int().positive().optional(),
});

export const exchangePreAuthorizedCodeInputSchema = z.object({
	tokenRequest: tokenRequestSchema,
	preAuthorizedGrant: preAuthorizedGrantRecordSchema,
});

export const accessTokenRecordSchema = z.object({
	accessToken: z.string().min(1),
	credentialConfigurationId: z.string().min(1),
	claims: claimSetSchema,
	expiresAt: z.number().int(),
	used: z.boolean(),
});

export const issueCredentialInputSchema = z.object({
	accessToken: accessTokenRecordSchema,
	credential_configuration_id: z.string().min(1),
	holderPublicJwk: jwkSchema.optional(),
	status: credentialStatusSchema.optional(),
});

export const nonceRecordSchema = z.object({
	c_nonce: z.string().min(1),
	expiresAt: z.number().int(),
	used: z.boolean(),
});

export const nonceResponseSchema = z.object({
	c_nonce: z.string().min(1),
	c_nonce_expires_in: z.number().int().positive(),
});

export const credentialRequestProofSchema = z.object({
	proof_type: z.literal("jwt"),
	jwt: z.string().min(1),
});

export const credentialRequestSchema = z.object({
	format: z.literal("dc+sd-jwt").optional(),
	credential_configuration_id: z.string().min(1),
	proofs: z.object({
		jwt: z.array(credentialRequestProofSchema).min(1),
	}),
});

export const credentialResponseSchema = z.object({
	format: z.literal("dc+sd-jwt"),
	credential: z.string().min(1),
	c_nonce: z.string().min(1).optional(),
	c_nonce_expires_in: z.number().int().positive().optional(),
});

export const validateProofJwtInputSchema = z.object({
	jwt: z.string().min(1),
	nonce: nonceRecordSchema,
});

export type Jwk = z.infer<typeof jwkSchema>;
export type ClaimSet = z.infer<typeof claimSetSchema>;
export type CreateStatusListInput = z.input<typeof createStatusListInputSchema>;
export type IssuerConfig = z.infer<typeof issuerConfigSchema>;
export type CredentialConfiguration = z.input<
	typeof credentialConfigurationSchema
>;
export type CredentialStatus = z.infer<typeof credentialStatusSchema>;
export type CredentialStatusListReference = z.infer<
	typeof credentialStatusListReferenceSchema
>;
export type IssuerConfigInput = z.input<typeof issuerConfigSchema>;
export type CreatePreAuthorizedGrantInput = z.input<
	typeof createPreAuthorizedGrantInputSchema
>;
export type CreateCredentialOfferInput = z.input<
	typeof createCredentialOfferInputSchema
>;
export type CredentialOffer = z.infer<typeof credentialOfferSchema>;
export type CredentialOfferUri = z.infer<typeof credentialOfferUriSchema>;
export type IssuerMetadataCredentialConfiguration = z.infer<
	typeof issuerMetadataCredentialConfigurationSchema
>;
export type IssuerMetadataPayload = z.infer<typeof issuerMetadataSchema>;
export type PreAuthorizedGrantRecord = z.infer<
	typeof preAuthorizedGrantRecordSchema
>;
export type TokenRequest = z.input<typeof tokenRequestSchema>;
export type TokenResponse = z.infer<typeof tokenResponseSchema>;
export type ExchangePreAuthorizedCodeInput = z.input<
	typeof exchangePreAuthorizedCodeInputSchema
>;
export type AccessTokenRecord = z.infer<typeof accessTokenRecordSchema>;
export type IssueCredentialInput = z.input<typeof issueCredentialInputSchema>;
export type NonceRecord = z.infer<typeof nonceRecordSchema>;
export type NonceResponse = z.infer<typeof nonceResponseSchema>;
export type StatusListBits = z.infer<typeof statusListBitsSchema>;
export type StatusListRecord = z.infer<typeof statusListRecordSchema>;
export type CredentialRequest = z.infer<typeof credentialRequestSchema>;
export type CredentialResponse = z.infer<typeof credentialResponseSchema>;
export type TokenStatusValue = z.infer<typeof tokenStatusValueSchema>;
export type ValidateProofJwtInput = z.input<typeof validateProofJwtInputSchema>;
