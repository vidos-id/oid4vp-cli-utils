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

export const tokenRequestSchema = z.object({
	grant_type: z.literal("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
	"pre-authorized_code": z.string().min(1),
	tx_code: z.string().min(1).optional(),
});

export const proofObjectSchema = z.object({
	proof_type: z.literal("jwt"),
	jwt: z.string().min(1),
});

export const credentialRequestSchema = z.object({
	access_token: z.string().min(1),
	credential_configuration_id: z.string().min(1),
	proof: proofObjectSchema.optional(),
	holderPublicJwk: jwkSchema.optional(),
});

export const nonceValidationSchema = z.object({
	jwt: z.string().min(1),
});

export type Jwk = z.infer<typeof jwkSchema>;
export type ClaimSet = z.infer<typeof claimSetSchema>;
export type IssuerConfig = z.infer<typeof issuerConfigSchema>;
export type CredentialConfiguration = z.input<
	typeof credentialConfigurationSchema
>;
export type IssuerConfigInput = z.input<typeof issuerConfigSchema>;
export type CreatePreAuthorizedGrantInput = z.input<
	typeof createPreAuthorizedGrantInputSchema
>;
export type CreateCredentialOfferInput = z.input<
	typeof createCredentialOfferInputSchema
>;
export type TokenRequest = z.input<typeof tokenRequestSchema>;
export type CredentialRequest = z.input<typeof credentialRequestSchema>;
export type NonceValidationInput = z.input<typeof nonceValidationSchema>;
