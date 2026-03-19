/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { decodeSdJwt, getClaims, splitSdJwt } from "@sd-jwt/decode";
import { exportJWK, generateKeyPair, importJWK, jwtVerify } from "jose";

import { issueDemoCredential, sdJwtHasher } from "./crypto.ts";
import { parseOid4VpAuthorizationUrl } from "./oid4vp.ts";
import { InMemoryWalletStorage } from "./storage.ts";
import { Wallet } from "./wallet.ts";

async function createIssuerFixture() {
	const { privateKey, publicKey } = await generateKeyPair("ES256", {
		extractable: true,
	});
	return {
		issuer: "https://issuer.example",
		privateJwk: await exportJWK(privateKey),
		publicJwk: await exportJWK(publicKey),
	};
}

describe("wallet", () => {
	test("generates and persists a holder key", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);

		const first = await wallet.getOrCreateHolderKey();
		const second = await wallet.getOrCreateHolderKey();

		expect(first.id).toBe(second.id);
		expect((await storage.getHolderKey())?.id).toBe(first.id);
	});

	test("imports and validates an issuer-bound dc+sd-jwt credential", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const holderKey = await wallet.getOrCreateHolderKey();
		const issuer = await createIssuerFixture();

		const credential = await issueDemoCredential({
			issuer: issuer.issuer,
			issuerPrivateJwk: issuer.privateJwk,
			holderPublicJwk: holderKey.publicJwk as never,
			vct: "https://example.com/PersonCredential",
			claims: {
				given_name: "Ada",
				family_name: "Lovelace",
				address: { locality: "London" },
			},
			disclosureFrame: {
				_sd: ["given_name", "family_name"],
				address: { _sd: ["locality"] },
			},
			issuedAt: 1,
		});

		const imported = await wallet.importCredential({
			credential,
			issuer: {
				issuer: issuer.issuer,
				jwks: { keys: [issuer.publicJwk as Record<string, unknown>] },
			},
		});

		expect(imported.issuer).toBe(issuer.issuer);
		expect(imported.vct).toBe("https://example.com/PersonCredential");
		expect(imported.claims).toEqual({
			given_name: "Ada",
			family_name: "Lovelace",
			address: { locality: "London" },
		});
		expect(await wallet.listCredentials()).toHaveLength(1);
	});

	test("matches a reduced dcql query", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const holderKey = await wallet.getOrCreateHolderKey();
		const issuer = await createIssuerFixture();

		const credential = await issueDemoCredential({
			issuer: issuer.issuer,
			issuerPrivateJwk: issuer.privateJwk,
			holderPublicJwk: holderKey.publicJwk as never,
			vct: "https://example.com/PersonCredential",
			claims: {
				given_name: "Ada",
				family_name: "Lovelace",
				address: { locality: "London" },
			},
			disclosureFrame: {
				_sd: ["given_name", "family_name"],
				address: { _sd: ["locality"] },
			},
			issuedAt: 1,
		});

		await wallet.importCredential({
			credential,
			issuer: {
				issuer: issuer.issuer,
				jwk: issuer.publicJwk as Record<string, unknown>,
			},
		});

		const match = await wallet.matchDcqlQuery({
			client_id: "https://verifier.example",
			nonce: "nonce-123",
			dcql_query: {
				credentials: [
					{
						id: "person_credential",
						format: "dc+sd-jwt",
						meta: { vct_values: ["https://example.com/PersonCredential"] },
						claims: [
							{ path: ["given_name"] },
							{ path: ["address", "locality"] },
						],
					},
				],
			},
		});

		expect(match.credentials).toHaveLength(1);
		expect(match.credentials[0]).toMatchObject({
			queryId: "person_credential",
			issuer: issuer.issuer,
			claimPaths: [["given_name"], ["address", "locality"]],
		});
	});

	test("parses a by-value oid4vp authorization URL", () => {
		const request = parseOid4VpAuthorizationUrl(
			`oid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&nonce=nonce-123&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [{ id: "person_credential", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/PersonCredential"] }, claims: [{ path: ["given_name"] }] }] }))}`,
		);

		expect(request).toEqual({
			client_id: "https://verifier.example",
			nonce: "nonce-123",
			response_type: "vp_token",
			dcql_query: {
				credentials: [
					{
						id: "person_credential",
						format: "dc+sd-jwt",
						meta: {
							vct_values: ["https://example.com/PersonCredential"],
						},
						claims: [{ path: ["given_name"] }],
					},
				],
			},
		});
	});

	test("rejects unsupported oid4vp request_uri input", () => {
		expect(() =>
			parseOid4VpAuthorizationUrl(
				"oid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&nonce=nonce-123&request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt",
			),
		).toThrow("request_uri is unsupported");
	});

	test("creates a selective disclosure presentation with kb-jwt", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const holderKey = await wallet.getOrCreateHolderKey();
		const issuer = await createIssuerFixture();

		const credential = await issueDemoCredential({
			issuer: issuer.issuer,
			issuerPrivateJwk: issuer.privateJwk,
			holderPublicJwk: holderKey.publicJwk as never,
			vct: "https://example.com/PersonCredential",
			claims: {
				given_name: "Ada",
				family_name: "Lovelace",
				address: { locality: "London", country: "UK" },
			},
			disclosureFrame: {
				_sd: ["given_name", "family_name"],
				address: { _sd: ["locality", "country"] },
			},
			issuedAt: 1,
		});

		await wallet.importCredential({
			credential,
			issuer: {
				issuer: issuer.issuer,
				jwk: issuer.publicJwk as Record<string, unknown>,
			},
		});

		const presentation = await wallet.createPresentation({
			client_id: "https://verifier.example",
			nonce: "nonce-456",
			dcql_query: {
				credentials: [
					{
						id: "person_credential",
						format: "dc+sd-jwt",
						meta: { vct_values: ["https://example.com/PersonCredential"] },
						claims: [
							{ path: ["given_name"] },
							{ path: ["address", "locality"] },
						],
					},
				],
			},
		});

		const compactPresentation =
			presentation.dcqlPresentation.person_credential?.[0];
		if (!compactPresentation) {
			throw new Error("Expected person_credential presentation");
		}
		const split = splitSdJwt(compactPresentation);
		expect(split.kbJwt).toBeDefined();

		const decoded = await decodeSdJwt(compactPresentation, sdJwtHasher);
		const claims = await getClaims<Record<string, unknown>>(
			decoded.jwt.payload,
			decoded.disclosures,
			sdJwtHasher,
		);

		expect(claims).toEqual({
			iss: issuer.issuer,
			vct: "https://example.com/PersonCredential",
			cnf: { jwk: holderKey.publicJwk },
			given_name: "Ada",
			address: { locality: "London" },
			iat: 1,
		});
		expect(claims.family_name).toBeUndefined();
		expect((claims.address as Record<string, unknown>).country).toBeUndefined();

		const holderPublicKey = await importJWK(holderKey.publicJwk, "ES256");
		if (!split.kbJwt) {
			throw new Error("Expected holder-bound presentation to include KB-JWT");
		}
		const kb = await jwtVerify(split.kbJwt, holderPublicKey, {
			typ: "kb+jwt",
			audience: "https://verifier.example",
		});

		expect(kb.payload.nonce).toBe("nonce-456");
		expect(typeof kb.payload.sd_hash).toBe("string");
	});

	test("creates a presentation using an explicit matched credential selection", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const holderKey = await wallet.getOrCreateHolderKey();
		const issuer = await createIssuerFixture();

		const credentialAda = await issueDemoCredential({
			issuer: issuer.issuer,
			issuerPrivateJwk: issuer.privateJwk,
			holderPublicJwk: holderKey.publicJwk as never,
			vct: "https://example.com/PersonCredential",
			claims: { given_name: "Ada" },
			disclosureFrame: { _sd: ["given_name"] },
			issuedAt: 1,
		});
		const credentialGrace = await issueDemoCredential({
			issuer: issuer.issuer,
			issuerPrivateJwk: issuer.privateJwk,
			holderPublicJwk: holderKey.publicJwk as never,
			vct: "https://example.com/PersonCredential",
			claims: { given_name: "Grace" },
			disclosureFrame: { _sd: ["given_name"] },
			issuedAt: 2,
		});

		const importedAda = await wallet.importCredential({
			credential: credentialAda,
			issuer: {
				issuer: issuer.issuer,
				jwk: issuer.publicJwk as Record<string, unknown>,
			},
		});
		const importedGrace = await wallet.importCredential({
			credential: credentialGrace,
			issuer: {
				issuer: issuer.issuer,
				jwk: issuer.publicJwk as Record<string, unknown>,
			},
		});

		const inspected = await wallet.inspectDcqlQuery({
			client_id: "https://verifier.example",
			nonce: "nonce-789",
			dcql_query: {
				credentials: [
					{
						id: "person_credential",
						format: "dc+sd-jwt",
						meta: { vct_values: ["https://example.com/PersonCredential"] },
						claims: [{ path: ["given_name"] }],
					},
				],
			},
		});

		expect(
			inspected.queries[0]?.credentials.map((item) => item.credentialId),
		).toEqual([importedAda.id, importedGrace.id]);

		const presentation = await wallet.createPresentation(
			{
				client_id: "https://verifier.example",
				nonce: "nonce-789",
				dcql_query: {
					credentials: [
						{
							id: "person_credential",
							format: "dc+sd-jwt",
							meta: { vct_values: ["https://example.com/PersonCredential"] },
							claims: [{ path: ["given_name"] }],
						},
					],
				},
			},
			{ selectedCredentials: { person_credential: importedGrace.id } },
		);

		expect(presentation.matchedCredentials[0]?.credentialId).toBe(
			importedGrace.id,
		);
	});
});
