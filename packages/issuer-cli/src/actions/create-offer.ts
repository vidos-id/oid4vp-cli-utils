import { createIssuer } from "issuer";
import {
	resolveCredentialConfigurationId,
	resolveIssuerConfig,
} from "../config.ts";
import { grantLikeOptionsSchema } from "../schemas.ts";
import { resolveClaims } from "./support.ts";

export async function createOfferAction(rawOptions: unknown) {
	const options = grantLikeOptionsSchema.parse(rawOptions);
	const config = await resolveIssuerConfig(options);
	const issuer = createIssuer(config);
	const credentialConfigurationId = resolveCredentialConfigurationId(
		config,
		options,
	);
	const claims = await resolveClaims(options.claims, options.claimsFile);
	return issuer.createCredentialOffer({
		credential_configuration_id: credentialConfigurationId,
		claims,
		expires_in: options.expiresIn,
	});
}
