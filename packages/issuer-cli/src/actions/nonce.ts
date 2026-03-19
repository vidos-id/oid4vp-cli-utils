import { createIssuer } from "issuer";
import { resolveIssuerConfig } from "../config.ts";
import { nonceOptionsSchema } from "../schemas.ts";

export async function nonceAction(rawOptions: unknown) {
	const options = nonceOptionsSchema.parse(rawOptions);
	const issuer = createIssuer(await resolveIssuerConfig(options));
	return issuer.createNonce();
}
