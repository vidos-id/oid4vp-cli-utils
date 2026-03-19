import { createIssuer } from "issuer";
import {
	resolveCredentialConfigurationId,
	resolveIssuerConfig,
} from "../config.ts";
import { issueOptionsSchema } from "../schemas.ts";
import { extractJwtNonce, resolveClaims, resolveProof } from "./support.ts";

export async function issueCredentialAction(rawOptions: unknown) {
	const options = issueOptionsSchema.parse(rawOptions);
	const config = await resolveIssuerConfig(options);
	const proof = await resolveProof(options.proof, options.proofFile);
	const proofNonce = extractJwtNonce(proof.jwt);
	const idSequence = options.accessToken
		? [proofNonce, `issued-nonce-${crypto.randomUUID()}`]
		: [
				`grant-${crypto.randomUUID()}`,
				`access-token-${crypto.randomUUID()}`,
				proofNonce,
				`issued-nonce-${crypto.randomUUID()}`,
			];
	let idIndex = 0;
	const issuer = createIssuer(config, {
		idGenerator: () => {
			const next = idSequence[idIndex];
			idIndex += 1;
			return next ?? crypto.randomUUID();
		},
	});
	const credentialConfigurationId = resolveCredentialConfigurationId(
		config,
		options,
	);

	let accessToken = options.accessToken;
	let derivedGrant:
		| {
				preAuthorizedCode: string;
				expiresAt: number;
				credential_configuration_id: string;
		  }
		| undefined;

	if (!accessToken) {
		const claims = await resolveClaims(options.claims, options.claimsFile);
		derivedGrant = issuer.createPreAuthorizedGrant({
			credential_configuration_id: credentialConfigurationId,
			claims,
		});
		const tokenResponse = issuer.exchangePreAuthorizedCode({
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": derivedGrant.preAuthorizedCode,
		});
		accessToken = tokenResponse.access_token;
	}
	issuer.createNonce();
	if (!accessToken) {
		throw new Error("Unable to resolve access token for issuance");
	}

	const issued = await issuer.issueCredential({
		access_token: accessToken,
		credential_configuration_id: credentialConfigurationId,
		proof,
	});

	return {
		...issued,
		credential_configuration_id: credentialConfigurationId,
		access_token: accessToken,
		pre_authorized_grant: derivedGrant,
	};
}
