import { jsonOutputFormatSchema, outputFormatSchema } from "cli-common";
import {
	claimSetSchema,
	issuerConfigSchema,
	jwkSchema,
	signingAlgSchema,
} from "issuer";
import { z } from "zod";

export {
	claimSetSchema,
	issuerConfigSchema,
	jsonOutputFormatSchema,
	outputFormatSchema,
};

export const commonIssuerOptionsSchema = z.object({
	issuer: z.string().url().optional(),
	issuerDir: z.string().optional(),
	signingKeyFile: z.string().optional(),
	vct: z.string().optional(),
});

export const issueOptionsSchema = commonIssuerOptionsSchema
	.extend({
		holderKeyFile: z.string().optional(),
		holderKey: z.string().optional(),
		credentialFile: z.string().optional(),
		claims: z.string().optional(),
		claimsFile: z.string().optional(),
		output: outputFormatSchema.default("json"),
	})
	.superRefine((value, ctx) => {
		if (!value.claims && !value.claimsFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"Provide --claims or --claims-file with the credential claim data",
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
		if (value.holderKey && value.holderKeyFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --holder-key or --holder-key-file",
				path: ["holderKey"],
			});
		}
	});

export const issuerInitOptionsSchema = z.object({
	issuerDir: z.string().min(1),
});

export const trustMaterialOptionsSchema = z.object({
	issuerDir: z.string().optional(),
	kid: z.string().min(1).optional(),
	alg: signingAlgSchema.optional(),
	subject: z.string().min(1).optional(),
	daysValid: z.coerce.number().int().positive().optional(),
});

export const importTrustMaterialOptionsSchema = z.object({
	issuerDir: z.string().min(1),
	privateKey: z.string().min(1),
	certificate: z.string().optional(),
	alg: signingAlgSchema.optional(),
});

export const signingKeyFileSchema = z.union([
	z.object({
		alg: signingAlgSchema.default("EdDSA"),
		privateJwk: jwkSchema,
		publicJwk: jwkSchema,
	}),
	z.object({
		signingKey: z.object({
			alg: signingAlgSchema.default("EdDSA"),
			privateJwk: jwkSchema,
			publicJwk: jwkSchema,
		}),
	}),
]);

export type CommonIssuerOptions = z.infer<typeof commonIssuerOptionsSchema>;
export type IssueOptions = z.infer<typeof issueOptionsSchema>;
