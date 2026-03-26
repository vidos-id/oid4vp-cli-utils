import { readFile } from "node:fs/promises";
import { verbose } from "@vidos-id/cli-common";
import type { z } from "zod";
import { resolveIssuerDirPaths } from "./paths.ts";
import {
	type commonIssuerOptionsSchema,
	issuerConfigSchema as issuerConfigValidator,
	signingKeyFileSchema,
} from "./schemas.ts";

export async function resolveIssuerConfig(
	options: z.infer<typeof commonIssuerOptionsSchema>,
) {
	const signingKeyFile =
		options.signingKeyFile ??
		resolveIssuerDirPaths(options.issuerDir as string).signingKeyFile;

	verbose(
		`Building inline config: issuer=${options.issuer}, vct=${options.vct}, signingKeyFile=${signingKeyFile}`,
	);
	const signingKey = await readSigningKeyFile(signingKeyFile as string);
	return issuerConfigValidator.parse({
		issuer: options.issuer,
		signingKey,
		credentialConfigurationsSupported: {
			credential: {
				format: "dc+sd-jwt",
				vct: options.vct,
			},
		},
	});
}

async function readSigningKeyFile(filePath: string) {
	verbose(`Reading signing key from ${filePath}`);
	const raw = JSON.parse(await readFile(filePath, "utf8")) as unknown;
	const parsed = signingKeyFileSchema.safeParse(raw);
	if (!parsed.success) {
		if (
			typeof raw === "object" &&
			raw !== null &&
			"jwks" in raw &&
			"certificatePem" in raw &&
			!("privateJwk" in raw) &&
			!("signingKey" in raw)
		) {
			throw new Error(
				`Invalid --signing-key-file: ${filePath} looks like verifier trust material and does not contain a private signing key. Regenerate it with:\n  issuer-cli generate-trust-material --signing-key-out <file>`,
			);
		}
		throw parsed.error;
	}
	return "signingKey" in parsed.data ? parsed.data.signingKey : parsed.data;
}
