import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createIssuer } from "issuer";
import { resolveIssuerConfig } from "../config.ts";
import { parseHolderPublicJwk, readHolderPublicJwk } from "../holder-key.ts";
import { issueOptionsSchema } from "../schemas.ts";
import { resolveClaims } from "./support.ts";

const CREDENTIAL_CONFIGURATION_ID = "credential";

export async function issueCredentialAction(rawOptions: unknown) {
	const options = issueOptionsSchema.parse(rawOptions);
	const config = await resolveIssuerConfig(options);
	const holderPublicJwk = options.holderKeyFile
		? await readHolderPublicJwk(options.holderKeyFile)
		: options.holderKey
			? parseHolderPublicJwk(options.holderKey)
			: undefined;
	const issuer = createIssuer(config);
	const claims = await resolveClaims(options.claims, options.claimsFile);
	const grant = issuer.createPreAuthorizedGrant({
		credential_configuration_id: CREDENTIAL_CONFIGURATION_ID,
		claims,
	});
	const token = issuer.exchangePreAuthorizedCode({
		grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		"pre-authorized_code": grant.preAuthorizedCode,
	});
	const issued = await issuer.issueCredential({
		access_token: token.access_token,
		credential_configuration_id: CREDENTIAL_CONFIGURATION_ID,
		holderPublicJwk,
	});
	if (options.issuerDir) {
		const filename =
			options.credentialFile ?? `credential-${crypto.randomUUID()}.txt`;
		const credentialPath = join(options.issuerDir, filename);
		try {
			await access(credentialPath);
			throw new Error(`Credential file already exists: ${filename}`);
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
				throw err;
			}
		}
		await writeFile(credentialPath, `${issued.credential}\n`, "utf8");
	}
	return {
		...issued,
		credential_configuration_id: CREDENTIAL_CONFIGURATION_ID,
		access_token: token.access_token,
	};
}
