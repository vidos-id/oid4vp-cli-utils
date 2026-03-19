import { createIssuer } from "issuer";
import { resolveIssuerConfig } from "../config.ts";
import { metadataOptionsSchema } from "../schemas.ts";

export async function metadataAction(rawOptions: unknown) {
	const options = metadataOptionsSchema.parse(rawOptions);
	const issuer = createIssuer(await resolveIssuerConfig(options));
	return issuer.getMetadata();
}
