import type { DcqlQuery } from "dcql";
import { z } from "zod";

export const JwkSchema = z
	.record(z.string(), z.unknown())
	.refine((value) => typeof value.kty === "string", "JWK must include kty");

export const HolderKeyRecordSchema = z.object({
	id: z.string().min(1),
	algorithm: z.literal("ES256"),
	publicJwk: JwkSchema,
	privateJwk: JwkSchema,
	createdAt: z.string().datetime(),
});

export const StoredCredentialRecordSchema = z.object({
	id: z.string().min(1),
	format: z.literal("dc+sd-jwt"),
	compactSdJwt: z.string().min(1),
	issuer: z.string().min(1),
	vct: z.string().min(1),
	holderKeyId: z.string().min(1),
	claims: z.record(z.string(), z.unknown()),
	importedAt: z.string().datetime(),
});

export const IssuerJwksSchema = z.object({
	issuer: z.string().min(1),
	jwks: z.object({
		keys: z.array(JwkSchema).min(1),
	}),
});

export const IssuerJwkSchema = z.object({
	issuer: z.string().min(1),
	jwk: JwkSchema,
});

export const IssuerKeyMaterialSchema = z.union([
	IssuerJwksSchema,
	IssuerJwkSchema,
]);

export const ImportCredentialInputSchema = z.object({
	credential: z.string().min(1),
	issuer: IssuerKeyMaterialSchema,
});

export const OpenId4VpRequestSchema = z
	.object({
		client_id: z.string().min(1),
		nonce: z.string().min(1),
		dcql_query: z.unknown(),
		response_type: z.literal("vp_token").optional(),
		scope: z.unknown().optional(),
		presentation_definition: z.unknown().optional(),
	})
	.superRefine((value, ctx) => {
		if (value.scope !== undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "scope-encoded queries are unsupported",
				path: ["scope"],
			});
		}

		if (value.presentation_definition !== undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Presentation Exchange is unsupported",
				path: ["presentation_definition"],
			});
		}

		if (
			value.response_type !== undefined &&
			value.response_type !== "vp_token"
		) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Only response_type=vp_token is supported",
				path: ["response_type"],
			});
		}
	});

export const WalletConfigSchema = z.object({
	storage: z.custom<unknown>(
		(value) => typeof value === "object" && value !== null,
		{
			message: "storage is required",
		},
	),
});

export type HolderKeyRecord = z.infer<typeof HolderKeyRecordSchema>;
export type StoredCredentialRecord = z.infer<
	typeof StoredCredentialRecordSchema
>;
export type IssuerKeyMaterial = z.infer<typeof IssuerKeyMaterialSchema>;
export type ImportCredentialInput = z.infer<typeof ImportCredentialInputSchema>;
export type OpenId4VpRequestInput = z.infer<typeof OpenId4VpRequestSchema>;

export type ParsedDcqlQuery = ReturnType<typeof DcqlQuery.parse>;
