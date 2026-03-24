import { resolveIssuerDirPaths } from "../paths.ts";
import { issuerInitOptionsSchema } from "../schemas.ts";
import { generateTrustMaterialAction } from "./generate-trust-material.ts";

export async function initIssuerAction(rawOptions: unknown) {
	const options = issuerInitOptionsSchema.parse(rawOptions);
	const paths = resolveIssuerDirPaths(options.issuerDir);
	await generateTrustMaterialAction({
		issuerDir: options.issuerDir,
		signingKeyOut: paths.signingKeyFile,
		jwksOut: paths.jwksFile,
		trustArtifactOut: paths.trustFile,
	});
	return {
		issuerDir: options.issuerDir,
		signingKeyFile: paths.signingKeyFile,
		jwksFile: paths.jwksFile,
		trustFile: paths.trustFile,
	};
}
