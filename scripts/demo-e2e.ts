import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { importJWK, SignJWT } from "jose";
import {
	type ClaimSet,
	createIssuer,
	generateIssuerTrustMaterial,
	jwkSchema,
} from "../packages/issuer/src/index.ts";
import { Wallet } from "../packages/wallet/src/index.ts";
import { FileSystemWalletStorage } from "../packages/wallet-cli/src/storage.ts";

async function createProofJwt(input: {
	aud: string;
	nonce: string;
	holderPrivateJwk: Record<string, unknown>;
	holderPublicJwk: Record<string, unknown>;
}) {
	const privateKey = await importJWK(input.holderPrivateJwk as never, "ES256");

	return new SignJWT({ aud: input.aud, nonce: input.nonce, iat: 1 })
		.setProtectedHeader({
			alg: "ES256",
			typ: "openid4vci-proof+jwt",
			jwk: input.holderPublicJwk,
		})
		.sign(privateKey);
}

const demoClaims: ClaimSet = {
	given_name: "Ada",
	family_name: "Lovelace",
	birth_date: "1815-12-10",
	address: {
		locality: "London",
		country: "GB",
	},
};

const request = {
	client_id: "https://verifier.example",
	nonce: "demo-verifier-nonce",
	dcql_query: {
		credentials: [
			{
				id: "person_credential",
				format: "dc+sd-jwt",
				meta: {
					vct_values: ["https://example.com/PersonCredential"],
				},
				claims: [{ path: ["given_name"] }, { path: ["address", "locality"] }],
			},
		],
	},
};

const workspace = await mkdtemp(join(tmpdir(), "oid4vp-cli-utils-demo-"));
const outputDir = join(workspace, "demo-output");
const walletDir = join(outputDir, "wallet");

await mkdir(walletDir, { recursive: true });

const trust = await generateIssuerTrustMaterial({
	kid: "demo-issuer-key",
	subject: "/CN=Demo Issuer/O=oid4vp-cli-utils",
});

const issuer = createIssuer({
	issuer: "https://issuer.example",
	signingKey: {
		alg: "EdDSA",
		privateJwk: jwkSchema.parse(trust.privateJwk),
		publicJwk: jwkSchema.parse(trust.publicJwk),
	},
	credentialConfigurationsSupported: {
		person: {
			format: "dc+sd-jwt",
			vct: "https://example.com/PersonCredential",
		},
	},
});

const wallet = new Wallet(new FileSystemWalletStorage(walletDir));
const holderKey = await wallet.getOrCreateHolderKey();
const issuerNonce = issuer.createNonce();
const proofJwt = await createProofJwt({
	aud: "https://issuer.example",
	nonce: issuerNonce.c_nonce,
	holderPrivateJwk: holderKey.privateJwk,
	holderPublicJwk: holderKey.publicJwk,
});

const grant = issuer.createPreAuthorizedGrant({
	credential_configuration_id: "person",
	claims: demoClaims,
});

const token = issuer.exchangePreAuthorizedCode({
	grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
	"pre-authorized_code": grant.preAuthorizedCode,
});

const issued = await issuer.issueCredential({
	access_token: token.access_token,
	credential_configuration_id: "person",
	proof: {
		proof_type: "jwt",
		jwt: proofJwt,
	},
});

const imported = await wallet.importCredential({
	credential: issued.credential,
	issuer: {
		issuer: "https://issuer.example",
		jwks: {
			keys: trust.jwks.keys.map((key) => jwkSchema.parse(key)),
		},
	},
});

const presentation = await wallet.createPresentation(request);

await writeFile(
	join(outputDir, "issuer-trust.json"),
	JSON.stringify(trust.trustArtifact, null, 2),
);
await writeFile(
	join(outputDir, "issuer-jwks.json"),
	JSON.stringify(trust.jwks, null, 2),
);
await writeFile(join(outputDir, "credential.txt"), issued.credential, "utf8");
await writeFile(
	join(outputDir, "request.json"),
	JSON.stringify(request, null, 2),
	"utf8",
);
await writeFile(
	join(outputDir, "presentation.json"),
	JSON.stringify(presentation, null, 2),
	"utf8",
);

const summary = {
	workspace,
	outputDir,
	issuedCredentialId: imported.id,
	walletDir,
	presentationKeys: Object.keys(presentation.dcqlPresentation),
	vpTokenPreview: `${presentation.vpToken.slice(0, 80)}...`,
};

process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
