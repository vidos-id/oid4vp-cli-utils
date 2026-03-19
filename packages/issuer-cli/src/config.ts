import { readFile } from "node:fs/promises";
import type { issuerConfigSchema } from "issuer";
import type { z } from "zod";
import {
	type commonIssuerOptionsSchema,
	issuerConfigSchema as issuerConfigValidator,
	signingKeyFileSchema,
} from "./schemas.ts";

export async function resolveIssuerConfig(
	options: z.infer<typeof commonIssuerOptionsSchema>,
) {
	const configFromFile = options.config
		? issuerConfigValidator.parse(
				JSON.parse(await readFile(options.config, "utf8")) as unknown,
			)
		: null;

	if (configFromFile) {
		if (!options.issuer) {
			return configFromFile;
		}
		return issuerConfigValidator.parse({
			...configFromFile,
			issuer: options.issuer,
		});
	}

	if (!options.issuer || !options.signingKeyFile || !options.vct) {
		throw new Error(
			"Inline issuer config requires --issuer, --signing-key-file, and --vct",
		);
	}

	const signingKey = await readSigningKeyFile(options.signingKeyFile);
	const credentialConfigurationId =
		options.credentialConfigurationId ?? "credential";
	return issuerConfigValidator.parse({
		issuer: options.issuer,
		signingKey,
		credentialConfigurationsSupported: {
			[credentialConfigurationId]: {
				format: "dc+sd-jwt",
				vct: options.vct,
			},
		},
	});
}

export function resolveCredentialConfigurationId(
	config: z.infer<typeof issuerConfigSchema>,
	options: z.infer<typeof commonIssuerOptionsSchema>,
): string {
	if (options.credentialConfigurationId) {
		if (
			!config.credentialConfigurationsSupported[
				options.credentialConfigurationId
			]
		) {
			throw new Error(
				`Unknown credential configuration id: ${options.credentialConfigurationId}`,
			);
		}
		return options.credentialConfigurationId;
	}

	if (options.vct) {
		const matches = Object.entries(
			config.credentialConfigurationsSupported,
		).filter(([, entry]) => entry.vct === options.vct);
		const matched = matches[0];
		if (matches.length === 1 && matched) {
			return matched[0];
		}
	}

	const ids = Object.keys(config.credentialConfigurationsSupported);
	const firstId = ids[0];
	if (ids.length === 1 && firstId) {
		return firstId;
	}

	throw new Error(
		"Provide --credential-configuration-id or a uniquely matching --vct",
	);
}

async function readSigningKeyFile(filePath: string) {
	const parsed = signingKeyFileSchema.parse(
		JSON.parse(await readFile(filePath, "utf8")) as unknown,
	);
	return "signingKey" in parsed ? parsed.signingKey : parsed;
}
