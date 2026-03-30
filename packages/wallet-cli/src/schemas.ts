import {
	jsonOutputFormatSchema,
	outputFormatSchema,
} from "@vidos-id/cli-common";
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

export const receiveOptionsSchema = z.object({
	walletDir: z.string().min(1),
	offer: z.string().min(1),
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

export const showOptionsSchema = z
	.object({
		walletDir: z.string().min(1),
		credentialId: z.string().min(1),
		resolveStatus: z.boolean().optional().default(false),
		output: outputFormatSchema.default("json"),
	})
	.superRefine((value, ctx) => {
		if (value.resolveStatus && value.output === "raw") {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "--resolve-status cannot be used with --output raw",
				path: ["resolveStatus"],
			});
		}
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
