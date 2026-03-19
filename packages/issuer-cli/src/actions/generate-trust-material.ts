import { generateIssuerTrustMaterial } from "issuer";
import { writeOptionalFile } from "../io.ts";
import { trustMaterialOptionsSchema } from "../schemas.ts";

export async function generateTrustMaterialAction(rawOptions: unknown) {
	const options = trustMaterialOptionsSchema.parse(rawOptions);
	const trust = await generateIssuerTrustMaterial({
		kid: options.kid,
		subject: options.subject,
		daysValid: options.daysValid,
	});

	await Promise.all([
		writeOptionalFile(options.privateJwkOut, trust.privateJwk),
		writeOptionalFile(options.publicJwkOut, trust.publicJwk),
		writeOptionalFile(options.jwksOut, trust.jwks),
		writeOptionalFile(options.privateKeyPemOut, trust.privateKeyPem),
		writeOptionalFile(options.publicKeyPemOut, trust.publicKeyPem),
		writeOptionalFile(options.certificateOut, trust.certificatePem),
		writeOptionalFile(options.trustArtifactOut, trust.trustArtifact),
	]);

	return trust;
}
