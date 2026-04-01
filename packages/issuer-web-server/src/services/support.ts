import { createIssuer, type StatusListRecord } from "@vidos-id/issuer";
import type { AppContext } from "../context.ts";
import { buildCredentialConfiguration, parseJwk } from "../utils.ts";
import { TemplateService } from "./templates.ts";

export async function buildIssuerInstance(app: AppContext) {
	const config = await app.db.query.issuerConfig.findFirst();
	const signingKey = await app.db.query.issuerSigningKeys.findFirst({
		where: (fields, operators) => operators.eq(fields.isActive, true),
	});
	const templates = await new TemplateService(app.db).listActive();
	if (!config || !signingKey) {
		throw new Error("Issuer bootstrap is incomplete");
	}
	return createIssuer({
		issuer: config.issuerUrl,
		signingKey: {
			alg: signingKey.alg as "ES256" | "ES384" | "EdDSA",
			privateJwk: parseJwk(signingKey.privateJwkJson),
			publicJwk: parseJwk(signingKey.publicJwkJson),
		},
		credentialConfigurationsSupported: Object.assign(
			{},
			...templates.map((template) =>
				buildCredentialConfiguration(
					template.credentialConfigurationId,
					template.vct,
				),
			),
		),
		endpoints: {
			token: new URL("/token", config.issuerUrl).toString(),
			credential: new URL("/credential", config.issuerUrl).toString(),
			nonce: new URL("/nonce", config.issuerUrl).toString(),
		},
		grantTtlSeconds: app.env.ISSUER_WEB_PRE_AUTHORIZED_CODE_TTL_SECONDS,
	});
}

export async function signStatusList(
	app: AppContext,
	statusList: StatusListRecord,
) {
	const issuer = await buildIssuerInstance(app);
	return issuer.createStatusListToken(statusList);
}
