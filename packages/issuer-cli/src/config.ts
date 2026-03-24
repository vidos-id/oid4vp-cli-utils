import { readFile } from "node:fs/promises";
import { verbose } from "cli-common";
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
		(options.issuerDir
			? resolveIssuerDirPaths(options.issuerDir).signingKeyFile
			: undefined);

	const provided: string[] = [];
	const missing: string[] = [];
	if (options.issuer) provided.push("--issuer");
	else missing.push("--issuer");
	if (signingKeyFile)
		provided.push(
			options.signingKeyFile ? "--signing-key-file" : "--issuer-dir",
		);
	else missing.push("--issuer-dir or --signing-key-file");
	if (options.vct) provided.push("--vct");
	else missing.push("--vct");

	if (missing.length > 0) {
		const providedText =
			provided.length > 0 ? ` You provided ${provided.join(", ")}.` : "";
		throw new Error(
			`Missing required options: ${missing.join(", ")}.${providedText}`,
		);
	}

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
