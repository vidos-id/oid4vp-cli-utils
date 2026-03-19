import { readFile } from "node:fs/promises";
import { type IssuerKeyMaterial, IssuerKeyMaterialSchema } from "wallet";
import { readTextInput } from "./io.ts";
import type { ImportOptions } from "./schemas.ts";

export async function resolveIssuerKeyMaterial(
	options: ImportOptions,
): Promise<IssuerKeyMaterial> {
	if (options.issuerMetadata || options.issuerMetadataFile) {
		return IssuerKeyMaterialSchema.parse(
			JSON.parse(
				await readTextInput(options.issuerMetadata, options.issuerMetadataFile),
			) as unknown,
		);
	}

	if (options.issuerJwksFile) {
		return IssuerKeyMaterialSchema.parse({
			issuer: options.issuer,
			jwks: JSON.parse(
				await readFile(options.issuerJwksFile, "utf8"),
			) as unknown,
		});
	}

	if (!options.issuerJwkFile) {
		throw new Error("issuer JWK file is required");
	}

	return IssuerKeyMaterialSchema.parse({
		issuer: options.issuer,
		jwk: JSON.parse(await readFile(options.issuerJwkFile, "utf8")) as unknown,
	});
}
