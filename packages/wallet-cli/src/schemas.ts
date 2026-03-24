import { jsonOutputFormatSchema, outputFormatSchema } from "cli-common";
import { z } from "zod";

export { jsonOutputFormatSchema, outputFormatSchema };

export const importOptionsSchema = z
	.object({
		walletDir: z.string().min(1),
		credential: z.string().optional(),
		credentialFile: z.string().optional(),
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
	});

export const listOptionsSchema = z.object({
	walletDir: z.string().min(1),
	vct: z.string().optional(),
	issuer: z.string().optional(),
});

export const initOptionsSchema = z.object({
	walletDir: z.string().min(1),
	alg: z.enum(["ES256", "ES384", "EdDSA"]).optional(),
	holderKeyFile: z.string().optional(),
});

export const showOptionsSchema = z.object({
	walletDir: z.string().min(1),
	credentialId: z.string().min(1),
	output: outputFormatSchema.default("json"),
});

export const presentOptionsSchema = z.object({
	walletDir: z.string().min(1),
	request: z.string().min(1),
	credentialId: z.string().optional(),
	dryRun: z.boolean().optional().default(false),
	output: outputFormatSchema.default("json"),
});

export type ImportOptions = z.infer<typeof importOptionsSchema>;
export type InitOptions = z.infer<typeof initOptionsSchema>;
