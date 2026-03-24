import { describe, expect, test } from "bun:test";
import { SDJwt } from "@sd-jwt/core";
import { hasher } from "@sd-jwt/hash";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generateIssuerTrustMaterial } from "./crypto.ts";
import { IssuerError } from "./errors.ts";
import { createIssuer } from "./issuer.ts";
import { jwkSchema } from "./schemas.ts";

const createTestIssuer = async () => {
	const trust = await generateIssuerTrustMaterial({
		kid: "issuer-key-1",
		subject: "/CN=Issuer Test",
	});
	const ids = ["grant-code-1", "access-token-1", "nonce-1", "issued-nonce-1"];
	let index = 0;
	const issuer = createIssuer(
		{
			issuer: "https://issuer.example",
			signingKey: {
				alg: "EdDSA",
				privateJwk: jwkSchema.parse(trust.privateJwk),
				publicJwk: jwkSchema.parse(trust.publicJwk),
			},
			credentialConfigurationsSupported: {
				employee_card: {
					format: "dc+sd-jwt",
					vct: "https://issuer.example/credentials/employee-card",
				},
			},
		},
		{
			now: () => 1_700_000_000,
			idGenerator: () => {
				const next = ids[index];
				index += 1;
				if (!next) {
					throw new Error("No more ids");
				}
				return next;
			},
		},
	);
	return { issuer, trust };
};

const createProofJwt = async (input: { aud: string; nonce: string }) => {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
		crv: "Ed25519",
		extractable: true,
	});
	const publicJwk = await exportJWK(publicKey);
	const jwt = await new SignJWT({
		aud: input.aud,
		nonce: input.nonce,
		iat: 1_700_000_000,
	})
		.setProtectedHeader({
			alg: "EdDSA",
			typ: "openid4vci-proof+jwt",
			jwk: publicJwk,
		})
		.sign(privateKey);
	return { jwt, publicJwk };
};

describe("issuer metadata and offers", () => {
	test("publishes metadata and pre-authorized offers", async () => {
		const { issuer, trust } = await createTestIssuer();
		const metadata = issuer.getMetadata();
		expect(metadata.credential_issuer).toBe("https://issuer.example");
		expect(metadata.token_endpoint).toBe("https://issuer.example/token");
		expect(metadata.nonce_endpoint).toBe("https://issuer.example/nonce");
		expect(metadata.jwks.keys[0]?.kid).toBe("issuer-key-1");
		expect(
			metadata.credential_configurations_supported.employee_card?.vct,
		).toBe("https://issuer.example/credentials/employee-card");

		const offer = issuer.createCredentialOffer({
			credential_configuration_id: "employee_card",
			claims: { given_name: "Ada", family_name: "Lovelace" },
		});
		expect(offer.credential_configuration_ids).toEqual(["employee_card"]);
		expect(
			offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
				"pre-authorized_code"
			],
		).toBe("grant-code-1");
		expect(trust.jwks.keys[0]?.kid).toBe("issuer-key-1");
	});
});

describe("token exchange and issuance", () => {
	test("exchanges code, validates proof, and issues a holder-bound dc+sd-jwt", async () => {
		const { issuer } = await createTestIssuer();
		issuer.createCredentialOffer({
			credential_configuration_id: "employee_card",
			claims: { given_name: "Ada", family_name: "Lovelace" },
		});
		const tokenResponse = issuer.exchangePreAuthorizedCode({
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": "grant-code-1",
		});
		expect(tokenResponse.access_token).toBe("access-token-1");

		const nonce = issuer.createNonce();
		expect(nonce.c_nonce).toBe("nonce-1");
		const proof = await createProofJwt({
			aud: "https://issuer.example",
			nonce: nonce.c_nonce,
		});
		const issued = await issuer.issueCredential({
			access_token: tokenResponse.access_token,
			credential_configuration_id: "employee_card",
			proof: { proof_type: "jwt", jwt: proof.jwt },
		});

		expect(issued.format).toBe("dc+sd-jwt");
		const parsed = await issuer.parseIssuedCredential(issued.credential);
		expect(parsed.header?.typ).toBe("dc+sd-jwt");
		expect(parsed.header?.kid).toBe("issuer-key-1");
		expect(Array.isArray(parsed.header?.x5c)).toBe(true);
		expect(parsed.payload?.vct).toBe(
			"https://issuer.example/credentials/employee-card",
		);
		expect(parsed.payload?.cnf).toEqual({ jwk: proof.publicJwk });

		const reconstructed = await (
			await SDJwt.fromEncode(issued.credential, hasher)
		).getClaims<Record<string, unknown>>(hasher);
		expect(reconstructed.given_name).toBe("Ada");
		expect(reconstructed.family_name).toBe("Lovelace");
	});

	test("ignores reserved claims from caller-provided claim sets", async () => {
		const { issuer } = await createTestIssuer();
		issuer.createCredentialOffer({
			credential_configuration_id: "employee_card",
			claims: {
				vct: "urn:eudi:pid:1",
				iss: "https://wrong.example",
				given_name: "Ada",
				family_name: "Lovelace",
			},
		});
		const tokenResponse = issuer.exchangePreAuthorizedCode({
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": "grant-code-1",
		});
		const nonce = issuer.createNonce();
		const proof = await createProofJwt({
			aud: "https://issuer.example",
			nonce: nonce.c_nonce,
		});
		const issued = await issuer.issueCredential({
			access_token: tokenResponse.access_token,
			credential_configuration_id: "employee_card",
			proof: { proof_type: "jwt", jwt: proof.jwt },
		});

		const parsed = await issuer.parseIssuedCredential(issued.credential);
		expect(parsed.payload?.iss).toBe("https://issuer.example");
		expect(parsed.payload?.vct).toBe(
			"https://issuer.example/credentials/employee-card",
		);
		const reconstructed = await (
			await SDJwt.fromEncode(issued.credential, hasher)
		).getClaims<Record<string, unknown>>(hasher);
		expect(reconstructed.given_name).toBe("Ada");
		expect(reconstructed.vct).toBe(
			"https://issuer.example/credentials/employee-card",
		);
	});

	test("issues without cnf when proof is omitted", async () => {
		const { issuer } = await createTestIssuer();
		issuer.createCredentialOffer({
			credential_configuration_id: "employee_card",
			claims: { given_name: "Ada" },
		});
		const tokenResponse = issuer.exchangePreAuthorizedCode({
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": "grant-code-1",
		});
		const issued = await issuer.issueCredential({
			access_token: tokenResponse.access_token,
			credential_configuration_id: "employee_card",
		});

		const parsed = await issuer.parseIssuedCredential(issued.credential);
		expect(parsed.payload?.cnf).toBeUndefined();
		const reconstructed = await (
			await SDJwt.fromEncode(issued.credential, hasher)
		).getClaims<Record<string, unknown>>(hasher);
		expect(reconstructed.given_name).toBe("Ada");
	});

	test("rejects tx_code and invalid proof audience", async () => {
		const { issuer } = await createTestIssuer();
		issuer.createCredentialOffer({
			credential_configuration_id: "employee_card",
			claims: { given_name: "Ada" },
		});
		expect(() =>
			issuer.exchangePreAuthorizedCode({
				grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
				"pre-authorized_code": "grant-code-1",
				tx_code: "1234",
			}),
		).toThrow(IssuerError);

		const tokenResponse = issuer.exchangePreAuthorizedCode({
			grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"pre-authorized_code": "grant-code-1",
		});
		const nonce = issuer.createNonce();
		const proof = await createProofJwt({
			aud: "https://wrong.example",
			nonce: nonce.c_nonce,
		});
		await expect(
			issuer.issueCredential({
				access_token: tokenResponse.access_token,
				credential_configuration_id: "employee_card",
				proof: { proof_type: "jwt", jwt: proof.jwt },
			}),
		).rejects.toThrow();
	});
});

describe("trust material generation", () => {
	test("returns jwks, pem, and self-signed certificate artifacts", async () => {
		const trust = await generateIssuerTrustMaterial({
			kid: "issuer-key-1",
			subject: "/CN=Issuer Trust Test",
		});
		expect(trust.publicKeyPem).toContain("BEGIN PUBLIC KEY");
		expect(trust.privateKeyPem).toContain("BEGIN PRIVATE KEY");
		expect(trust.certificatePem).toContain("BEGIN CERTIFICATE");
		expect(trust.jwks.keys[0]?.kid).toBe("issuer-key-1");
		expect(Array.isArray(trust.jwks.keys[0]?.x5c)).toBe(true);
		expect(
			trust.trustArtifact.certificateFingerprintSha256.length,
		).toBeGreaterThan(10);
	});
});
