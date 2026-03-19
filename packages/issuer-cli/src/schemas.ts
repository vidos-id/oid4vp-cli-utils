import {
	claimSetSchema,
	issuerConfigSchema,
	jwkSchema,
	proofObjectSchema,
} from "issuer";
import { z } from "zod";

export { claimSetSchema, issuerConfigSchema, proofObjectSchema };

export const outputFormatSchema = z.enum(["json", "pretty", "raw"]);
export const prettyOutputFormatSchema = z.enum(["json", "pretty"]);

export const commonIssuerOptionsSchema = z.object({
	config: z.string().optional(),
	issuer: z.string().url().optional(),
	signingKeyFile: z.string().optional(),
	credentialConfigurationId: z.string().optional(),
	vct: z.string().optional(),
});

export const grantLikeOptionsSchema = commonIssuerOptionsSchema
	.extend({
		claims: z.string().optional(),
		claimsFile: z.string().optional(),
		expiresIn: z.coerce.number().int().positive().optional(),
		output: outputFormatSchema.default("pretty"),
	})
	.superRefine((value, ctx) => {
		if (!value.claims && !value.claimsFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Provide --claims or --claims-file",
				path: ["claims"],
			});
		}
		if (value.claims && value.claimsFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --claims or --claims-file",
				path: ["claims"],
			});
		}
	});

export const metadataOptionsSchema = commonIssuerOptionsSchema.extend({
	output: prettyOutputFormatSchema.default("pretty"),
});

export const nonceOptionsSchema = commonIssuerOptionsSchema.extend({
	output: prettyOutputFormatSchema.default("pretty"),
});

export const issueOptionsSchema = commonIssuerOptionsSchema
	.extend({
		accessToken: z.string().optional(),
		claims: z.string().optional(),
		claimsFile: z.string().optional(),
		proof: z.string().optional(),
		proofFile: z.string().optional(),
		output: outputFormatSchema.default("pretty"),
	})
	.superRefine((value, ctx) => {
		if (!value.proof && !value.proofFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Provide --proof or --proof-file",
				path: ["proof"],
			});
		}
		if (value.proof && value.proofFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --proof or --proof-file",
				path: ["proof"],
			});
		}
		if (!value.accessToken && !value.claims && !value.claimsFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"Provide --access-token or let the command derive one with --claims/--claims-file",
				path: ["accessToken"],
			});
		}
		if (value.claims && value.claimsFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --claims or --claims-file",
				path: ["claims"],
			});
		}
	});

export const trustMaterialOptionsSchema = z.object({
	kid: z.string().min(1).optional(),
	subject: z.string().min(1).optional(),
	daysValid: z.coerce.number().int().positive().optional(),
	privateJwkOut: z.string().optional(),
	publicJwkOut: z.string().optional(),
	jwksOut: z.string().optional(),
	privateKeyPemOut: z.string().optional(),
	publicKeyPemOut: z.string().optional(),
	certificateOut: z.string().optional(),
	trustArtifactOut: z.string().optional(),
	output: prettyOutputFormatSchema.default("pretty"),
});

export const signingKeyFileSchema = z.union([
	z.object({
		alg: z.literal("EdDSA").default("EdDSA"),
		privateJwk: jwkSchema,
		publicJwk: jwkSchema,
	}),
	z.object({
		signingKey: z.object({
			alg: z.literal("EdDSA").default("EdDSA"),
			privateJwk: jwkSchema,
			publicJwk: jwkSchema,
		}),
	}),
]);

export type CommonIssuerOptions = z.infer<typeof commonIssuerOptionsSchema>;
export type MetadataOptions = z.infer<typeof metadataOptionsSchema>;
export type GrantLikeOptions = z.infer<typeof grantLikeOptionsSchema>;
export type IssueOptions = z.infer<typeof issueOptionsSchema>;
