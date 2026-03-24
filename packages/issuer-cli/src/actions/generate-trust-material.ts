import { writeOptionalFile } from "cli-common";
import { generateIssuerTrustMaterial } from "issuer";
import { resolveIssuerDirPaths } from "../paths.ts";
import { trustMaterialOptionsSchema } from "../schemas.ts";

export async function generateTrustMaterialAction(rawOptions: unknown) {
	const options = trustMaterialOptionsSchema.parse(rawOptions);
	const issuerPaths = options.issuerDir
		? resolveIssuerDirPaths(options.issuerDir)
		: undefined;
	const trust = await generateIssuerTrustMaterial({
		kid: options.kid,
		subject: options.subject,
		daysValid: options.daysValid,
		alg: options.alg,
	});

	await Promise.all([
		writeOptionalFile(issuerPaths?.signingKeyFile, {
			alg: trust.alg,
			privateJwk: trust.privateJwk,
			publicJwk: trust.publicJwk,
		}),
		writeOptionalFile(issuerPaths?.jwksFile, trust.jwks),
		writeOptionalFile(issuerPaths?.trustFile, trust.trustArtifact),
	]);

	return trust;
}
