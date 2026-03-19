import { z } from "zod";

export const outputFormatSchema = z.enum(["json", "pretty", "raw"]);
export const prettyOutputFormatSchema = z.enum(["json", "pretty"]);

export const importOptionsSchema = z
	.object({
		walletDir: z.string().min(1),
		credential: z.string().optional(),
		credentialFile: z.string().optional(),
		issuer: z.string().optional(),
		issuerMetadata: z.string().optional(),
		issuerMetadataFile: z.string().optional(),
		issuerJwksFile: z.string().optional(),
		issuerJwkFile: z.string().optional(),
		output: prettyOutputFormatSchema.default("pretty"),
	})
	.superRefine((value, ctx) => {
		if (!value.credential && !value.credentialFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Provide --credential or --credential-file",
				path: ["credential"],
			});
		}
		if (value.credential && value.credentialFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --credential or --credential-file",
				path: ["credential"],
			});
		}
		if (value.issuerMetadata && value.issuerMetadataFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --issuer-metadata or --issuer-metadata-file",
				path: ["issuerMetadata"],
			});
		}
		if (!value.issuerMetadata && !value.issuerMetadataFile) {
			if (!value.issuer) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "Provide --issuer when issuer metadata is not supplied",
					path: ["issuer"],
				});
			}
			if (!value.issuerJwksFile && !value.issuerJwkFile) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message:
						"Provide --issuer-jwks-file or --issuer-jwk-file when issuer metadata is not supplied",
					path: ["issuerJwksFile"],
				});
			}
		}
		if (value.issuerJwksFile && value.issuerJwkFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --issuer-jwks-file or --issuer-jwk-file",
				path: ["issuerJwksFile"],
			});
		}
	});

export const listOptionsSchema = z.object({
	walletDir: z.string().min(1),
	vct: z.string().optional(),
	issuer: z.string().optional(),
	output: prettyOutputFormatSchema.default("pretty"),
});

export const showOptionsSchema = z.object({
	walletDir: z.string().min(1),
	credentialId: z.string().min(1),
	output: outputFormatSchema.default("pretty"),
});

export const presentOptionsSchema = z
	.object({
		walletDir: z.string().min(1),
		request: z.string().optional(),
		requestFile: z.string().optional(),
		credentialId: z.string().optional(),
		output: outputFormatSchema.default("pretty"),
	})
	.superRefine((value, ctx) => {
		if (!value.request && !value.requestFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Provide --request or --request-file",
				path: ["request"],
			});
		}
		if (value.request && value.requestFile) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Use only one of --request or --request-file",
				path: ["request"],
			});
		}
	});

export type ImportOptions = z.infer<typeof importOptionsSchema>;
