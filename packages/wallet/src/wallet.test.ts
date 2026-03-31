/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { decodeSdJwt, getClaims, splitSdJwt } from "@sd-jwt/decode";
import {
	base64url,
	decodeJwt,
	exportJWK,
	generateKeyPair,
	importJWK,
	importX509,
	jwtDecrypt,
	jwtVerify,
	SignJWT,
} from "jose";
import {
	type AccessTokenRecord,
	createIssuer,
	generateIssuerTrustMaterial,
	jwkSchema,
	type NonceRecord,
	type PreAuthorizedGrantRecord,
} from "../../issuer/src/index.ts";

import { issueDemoCredential, sdJwtHasher } from "./crypto.ts";
import {
	parseCredentialOffer,
	receiveCredentialFromOffer,
} from "./openid4vci.ts";
import {
	createOpenId4VpAuthorizationResponse,
	parseOpenid4VpAuthorizationUrl,
	resolveOpenId4VpRequest,
	submitOpenId4VpAuthorizationResponse,
} from "./openid4vp.ts";
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

async function createOid4VciIssuerFixture() {
	const trust = await generateIssuerTrustMaterial({
		alg: "ES256",
		kid: "issuer-key-1",
		subject: "/CN=Issuer Test",
	});
	return createIssuer(
		{
			issuer: "https://issuer.example",
			signingKey: {
				alg: trust.alg,
				privateJwk: jwkSchema.parse(trust.privateJwk),
				publicJwk: jwkSchema.parse(trust.publicJwk),
			},
			credentialConfigurationsSupported: {
				person: {
					format: "dc+sd-jwt",
					vct: "https://example.com/PersonCredential",
					scope: "PersonCredential",
				},
			},
		},
		{
			now: () => 1_700_000_000,
			idGenerator: (() => {
				const ids = [
					"grant-code-1",
					"access-token-1",
					"nonce-1",
					"issued-nonce-1",
				];
				let index = 0;
				return () => ids[index++] as string;
			})(),
		},
	);
}

async function createRequestObject(
	claims: Record<string, unknown>,
): Promise<string> {
	const { privateKey } = await generateKeyPair("ES256");
	return new SignJWT(claims)
		.setProtectedHeader({ alg: "ES256", typ: "oauth-authz-req+jwt" })
		.sign(privateKey);
}

async function withMockedFetch(
	mock: (
		input: RequestInfo | URL,
		init?: RequestInit | BunFetchRequestInit,
	) => Promise<Response>,
	run: () => Promise<void>,
): Promise<void> {
	const originalFetch = globalThis.fetch;
	globalThis.fetch = mock as typeof fetch;
	try {
		await run();
	} finally {
		globalThis.fetch = originalFetch;
	}
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

	test("parses a by-value openid-credential-offer URI", () => {
		const parsed = parseCredentialOffer(
			`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify({ credential_issuer: "https://issuer.example", credential_configuration_ids: ["person"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "grant-code-1" } } }))}`,
		);

		expect(parsed.credential_issuer).toBe("https://issuer.example");
		expect(parsed.credential_configuration_ids).toEqual(["person"]);
	});

	test("receives a credential from an OID4VCI offer and stores it", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const issuer = await createOid4VciIssuerFixture();
		const statusList = issuer.createStatusList({
			uri: "https://issuer.example/status-lists/1",
			bits: 2,
		});
		const allocatedStatus = issuer.allocateCredentialStatus({ statusList });
		let currentStatusList = allocatedStatus.updatedStatusList;
		const offer = issuer.createCredentialOffer({
			credential_configuration_id: "person",
			claims: { given_name: "Ada", family_name: "Lovelace" },
		});
		let currentGrant: PreAuthorizedGrantRecord = offer.preAuthorizedGrant;
		let currentAccessToken: AccessTokenRecord | null = null;
		let currentNonce: NonceRecord | null = null;

		await withMockedFetch(
			async (input, init) => {
				const url = String(input);
				if (
					url === "https://issuer.example/.well-known/openid-credential-issuer"
				) {
					return Response.json(issuer.getMetadata());
				}
				if (url === "https://issuer.example/token") {
					const body = new URLSearchParams(String(init?.body));
					const tokenResponse = issuer.exchangePreAuthorizedCode({
						tokenRequest: {
							grant_type:
								"urn:ietf:params:oauth:grant-type:pre-authorized_code",
							"pre-authorized_code": body.get("pre-authorized_code") ?? "",
						},
						preAuthorizedGrant: currentGrant,
					});
					currentGrant = tokenResponse.updatedPreAuthorizedGrant;
					currentAccessToken = tokenResponse.accessTokenRecord;
					return Response.json(tokenResponse);
				}
				if (url === "https://issuer.example/nonce") {
					expect(init?.method).toBe("POST");
					const nonce = issuer.createNonce();
					currentNonce = nonce.nonce;
					return Response.json({
						c_nonce: nonce.c_nonce,
						c_nonce_expires_in: nonce.c_nonce_expires_in,
					});
				}
				if (url === "https://issuer.example/credential") {
					if (!currentAccessToken || !currentNonce) {
						throw new Error("Missing token or nonce state");
					}
					const request = JSON.parse(String(init?.body)) as {
						credential_configuration_id: string;
						proofs: { jwt: Array<{ jwt: string }> };
					};
					const proof = await issuer.validateProofJwt({
						jwt: request.proofs.jwt[0]?.jwt ?? "",
						nonce: currentNonce,
					});
					const issued = await issuer.issueCredential({
						accessToken: currentAccessToken,
						credential_configuration_id: request.credential_configuration_id,
						proof,
						status: allocatedStatus.credentialStatus,
					});
					currentAccessToken = issued.updatedAccessToken;
					return Response.json(issued);
				}
				if (url === "https://issuer.example/status-lists/1") {
					return new Response(
						await issuer.createStatusListToken(currentStatusList),
						{
							headers: { "content-type": "application/statuslist+jwt" },
						},
					);
				}
				throw new Error(`Unexpected fetch ${url}`);
			},
			async () => {
				const stored = await receiveCredentialFromOffer(wallet, offer);
				expect(stored.issuer).toBe("https://issuer.example");
				expect(stored.vct).toBe("https://example.com/PersonCredential");
				expect(stored.claims).toEqual({
					given_name: "Ada",
					family_name: "Lovelace",
				});
				expect(stored.status).toEqual(allocatedStatus.credentialStatus);
				expect((await wallet.getCredentialStatus(stored.id))?.status).toEqual({
					value: 0,
					label: "VALID",
					isValid: true,
				});
				currentStatusList = issuer.updateCredentialStatus({
					statusList: currentStatusList,
					idx: 0,
					status: 1,
				});
				expect((await wallet.getCredentialStatus(stored.id))?.status).toEqual({
					value: 1,
					label: "INVALID",
					isValid: false,
				});
				expect(await wallet.listCredentials()).toHaveLength(1);
			},
		);
	});

	test("receives a credential from a credential_offer_uri and stores it", async () => {
		const storage = new InMemoryWalletStorage();
		const wallet = new Wallet(storage);
		const issuer = await createOid4VciIssuerFixture();
		const statusList = issuer.createStatusList({
			uri: "https://issuer.example/status-lists/1",
			bits: 2,
		});
		const allocatedStatus = issuer.allocateCredentialStatus({ statusList });
		const offerReference =
			"openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fperson-1";
		let currentGrant: PreAuthorizedGrantRecord | null = null;
		let currentAccessToken: AccessTokenRecord | null = null;
		let currentNonce: NonceRecord | null = null;

		await withMockedFetch(
			async (input, init) => {
				const url = String(input);
				if (url === "https://issuer.example/offers/person-1") {
					const offer = issuer.createCredentialOffer({
						credential_configuration_id: "person",
						claims: { given_name: "Ada", family_name: "Lovelace" },
					});
					currentGrant = offer.preAuthorizedGrant;
					return Response.json(offer);
				}
				if (
					url === "https://issuer.example/.well-known/openid-credential-issuer"
				) {
					return Response.json(issuer.getMetadata());
				}
				if (url === "https://issuer.example/token") {
					if (!currentGrant) {
						throw new Error("Missing offer state");
					}
					const body = new URLSearchParams(String(init?.body));
					const tokenResponse = issuer.exchangePreAuthorizedCode({
						tokenRequest: {
							grant_type:
								"urn:ietf:params:oauth:grant-type:pre-authorized_code",
							"pre-authorized_code": body.get("pre-authorized_code") ?? "",
						},
						preAuthorizedGrant: currentGrant,
					});
					currentGrant = tokenResponse.updatedPreAuthorizedGrant;
					currentAccessToken = tokenResponse.accessTokenRecord;
					return Response.json(tokenResponse);
				}
				if (url === "https://issuer.example/nonce") {
					expect(init?.method).toBe("POST");
					const nonce = issuer.createNonce();
					currentNonce = nonce.nonce;
					return Response.json({
						c_nonce: nonce.c_nonce,
						c_nonce_expires_in: nonce.c_nonce_expires_in,
					});
				}
				if (url === "https://issuer.example/credential") {
					if (!currentAccessToken || !currentNonce) {
						throw new Error("Missing token or nonce state");
					}
					const request = JSON.parse(String(init?.body)) as {
						credential_configuration_id: string;
						proofs: { jwt: Array<{ jwt: string }> };
					};
					const proof = await issuer.validateProofJwt({
						jwt: request.proofs.jwt[0]?.jwt ?? "",
						nonce: currentNonce,
					});
					const issued = await issuer.issueCredential({
						accessToken: currentAccessToken,
						credential_configuration_id: request.credential_configuration_id,
						proof,
						status: allocatedStatus.credentialStatus,
					});
					currentAccessToken = issued.updatedAccessToken;
					return Response.json(issued);
				}
				throw new Error(`Unexpected fetch ${url}`);
			},
			async () => {
				const stored = await receiveCredentialFromOffer(wallet, offerReference);
				expect(stored.issuer).toBe("https://issuer.example");
				expect(stored.claims).toEqual({
					given_name: "Ada",
					family_name: "Lovelace",
				});
			},
		);
	});

	test("verifies the provided sd-jwt presentation kb-jwt signature", async () => {
		const presentation =
			"eyJ0eXAiOiJkYytzZC1qd3QiLCJraWQiOiJpc3N1ZXIta2V5LTEiLCJ4NWMiOlsiTUlJQmR6Q0NBU21nQXdJQkFnSVVMQTVLYjhZTVlLZlRlcmpobzJQRER4eERteXN3QlFZREsyVndNREV4RkRBU0JnTlZCQU1NQzBSbGJXOGdTWE56ZFdWeU1Sa3dGd1lEVlFRS0RCQnZhV1EwZG5BdFkyeHBMWFYwYVd4ek1CNFhEVEkyTURNeU16RTJNRFExT1ZvWERUSTNNRE15TXpFMk1EUTFPVm93TVRFVU1CSUdBMVVFQXd3TFJHVnRieUJKYzNOMVpYSXhHVEFYQmdOVkJBb01FRzlwWkRSMmNDMWpiR2t0ZFhScGJITXdLakFGQmdNclpYQURJUUNsSWJ4NFR3bHRMVnc2Q0tRUmpKZTFMbVlSQ1gwdzZtWW1haHpYaEI0UGFxTlRNRkV3SFFZRFZSME9CQllFRkUzTDRCK0ZZOGVIWVFySHVEOXkxYUhaNGttek1COEdBMVVkSXdRWU1CYUFGRTNMNEIrRlk4ZUhZUXJIdUQ5eTFhSFo0a216TUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3QlFZREsyVndBMEVBVTJmTjMrdXNUTFV2OXc1bWZvczNPb3BKSFVac3ErdlltVkQ2c1NnQmljK1c1MWhwbE4wMHNLS2RLS1R5N3RSWEI5K1hUSWdPMkNxTnlQaGc2WElGQUE9PSJdLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiaWF0IjoxNzc0MjgxOTA2LCJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2IiwieCI6IkdjU0FvWElXUEtDcEd1U3JhbVIzRUpQd1lYdjZpLTdrOEJmUmRHdHdIeEkiLCJ5IjoiTHRSb0YxWC1WdTludEhpQXI0VTY1alU0SGJJS2VySDJDelVkQmxvNFZ6RSIsInVzZSI6InNpZyJ9fSwiX3NkIjpbIjBCVzY4Z05rLTVqX3l2dDRWSjZUMUlnSjY1UEdOWnh1SWpIdC1ZSUM0ZmMiLCI3MmZpMVc5TnQ2UFRhMk10dUxqMVcwWndQNWZHd2pWWFo3QkJUMHBEcTJ3IiwiVy10cGFvbUZHVU5ic3NWLXB0MVFqTDloYWl0QlN5WXRIZEd5MWVoU0ZLWSIsIldPTEU0QURPMElqSGU5Ry1uUWpRcS1EQjU2N0JuNXBOeVA0UnFhaE1FT1EiLCJZOFpqRi1aV3pfZ2tKUTRoXzl0MWlHN1NqQkZXdWdPMWtpVVhRWldDYkt3IiwiZl9pZF93cERveWc2NnYySEdaY21ROUpGRURKQWZmUUQ3bFNsUDN3SmVlNCIsImswZ3BscHFRV2dmaW9IbmxqMjUyTllXQWtNSS02YXhLV1VjUUt4bzNZMmsiLCJwd1FLcFgyajVQRXhpajFsWjlHVEZ5RVBRWDltaDZ6RlpVUXlfU3BLeHJjIiwic0w3MXgxcnR4bGdJSldtWmFrNDFiRGZETkc4czduM1dVVE1KSWw1b0l2TSIsIngtMzh3NkwyNDMwVFp6emtoSlNqRHdjT3BiMTdHSWJhSGsxekJhaE9IZzQiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.a_mT5TdLCZbl2KqQ09WVucLSI-ttHHL1VwknJJQmYduf-ASArGh98uW7zvm8JQhwsA0UEaRMPtFNDAugzJ7WAg~WyJOQnFKWE9CdmhoenJXSXlqNDdrbWlnIiwiZmFtaWx5X25hbWUiLCJMb3ZlbGFjZSJd~WyJoRmp6RHdLaWlDTU4wY0NfNzlQYW1RIiwiZ2l2ZW5fbmFtZSIsIkFkYSJd~WyJnZVFhdWxhaGtPcjBRU244a0gwdkhBIiwiYmlydGhkYXRlIiwiMTgxNS0xMi0xMCJd~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJ4NTA5X3Nhbl9kbnM6ZXhwbGljaXQtYXF1YW1hcmluZS1tYWNrZXJlbC01MTQuZ2F0ZXdheS5zZXJ2aWNlLmV1LnZpZG9zLmRldiIsIm5vbmNlIjoibi02MjU4MGFkMC1lM2NlLTRjYWEtOWRhNS02Y2ZlNWYyYmI1NjQiLCJzZF9oYXNoIjoiMkMybVhDaUxQNUluVU9ZQXBDOFl3MFNkMmN2VDE2UjlTSnloSkpuYlNKMCIsImlhdCI6MTc3NDI4MTk5Mn0.MOl_CrBYz7r_1pJQ9IrGEZkK94JsUb7_WGC0QIwJOAOpwfIPrX_1UXj7qM7dlqW0h7BdYf6a71HJuAjNfXneHw";

		const split = splitSdJwt(presentation);
		if (!split.kbJwt) {
			throw new Error("Expected kb-jwt in presentation");
		}
		const credentialHeader = JSON.parse(
			Buffer.from(split.jwt.split(".")[0] ?? "", "base64url").toString("utf8"),
		) as { alg?: string; x5c?: string[] };

		const issuerJwt = decodeJwt(split.jwt) as Record<string, unknown>;
		const cnf = issuerJwt.cnf as { jwk?: Record<string, unknown> };
		if (!cnf?.jwk) {
			throw new Error("Expected cnf.jwk in credential payload");
		}
		const certificate = credentialHeader.x5c?.[0];
		if (!certificate) {
			throw new Error("Expected x5c certificate in credential header");
		}
		const issuerPublicKey = await importX509(
			`-----BEGIN CERTIFICATE-----\n${certificate.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----`,
			credentialHeader.alg ?? "EdDSA",
		);
		await jwtVerify(split.jwt, issuerPublicKey, {
			issuer: "https://issuer.example",
			typ: "dc+sd-jwt",
		});

		const kbHeader = split.kbJwt.split(".")[0];
		if (!kbHeader) {
			throw new Error("Expected kb-jwt header");
		}
		const protectedHeader = JSON.parse(
			Buffer.from(kbHeader, "base64url").toString("utf8"),
		) as { alg?: string; typ?: string };

		const holderPublicKey = await importJWK(cnf.jwk);
		const verified = await jwtVerify(split.kbJwt, holderPublicKey, {
			typ: "kb+jwt",
			audience:
				"x509_san_dns:explicit-aquamarine-mackerel-514.gateway.service.eu.vidos.dev",
		});
		const sdJwtWithoutKb = `${split.jwt}~${split.disclosures.join("~")}~`;
		const expectedSdHash = base64url.encode(
			new Uint8Array(
				await crypto.subtle.digest(
					"SHA-256",
					new TextEncoder().encode(sdJwtWithoutKb),
				),
			),
		);

		expect(protectedHeader.typ).toBe("kb+jwt");
		expect(verified.protectedHeader.alg).toBe("ES256");
		expect(verified.payload.nonce).toBe(
			"n-62580ad0-e3ce-4caa-9da5-6cfe5f2bb564",
		);
		expect(verified.payload.sd_hash).toBe(expectedSdHash);
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

	test("parses a by-value openid4vp authorization URL", async () => {
		const request = await parseOpenid4VpAuthorizationUrl(
			`openid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&nonce=nonce-123&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [{ id: "person_credential", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/PersonCredential"] }, claims: [{ path: ["given_name"] }] }] }))}`,
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

	test("parses a request object passed by value", async () => {
		const requestObject = await createRequestObject({
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

		const request = await resolveOpenId4VpRequest({
			client_id: "https://verifier.example",
			request: requestObject,
		});

		expect(request.nonce).toBe("nonce-123");
		expect(request.dcql_query).toEqual({
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
		});
	});

	test("preserves response submission parameters", async () => {
		const request = await resolveOpenId4VpRequest({
			client_id: "https://verifier.example",
			nonce: "nonce-123",
			state: "state-123",
			response_mode: "direct_post",
			response_uri: "https://verifier.example/response",
			client_metadata: {
				jwks: {
					keys: [{ kty: "EC", crv: "P-256", x: "x", y: "y", kid: "k1" }],
				},
			},
			dcql_query: {
				credentials: [
					{
						id: "person_credential",
						format: "dc+sd-jwt",
						meta: { vct_values: ["https://example.com/PersonCredential"] },
					},
				],
			},
		});

		expect(request.state).toBe("state-123");
		expect(request.response_mode).toBe("direct_post");
		expect(request.response_uri).toBe("https://verifier.example/response");
		expect(request.client_metadata?.jwks?.keys).toHaveLength(1);
	});

	test("fetches and parses a request object from request_uri", async () => {
		const requestObject = await createRequestObject({
			client_id: "x509_san_dns:verifier.example",
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

		await withMockedFetch(
			async (input, init) => {
				expect(String(input)).toBe("https://verifier.example/request.jwt");
				expect(init?.headers).toEqual({
					accept: "application/oauth-authz-req+jwt",
				});
				return new Response(requestObject, {
					status: 200,
					headers: {
						"content-type": "application/oauth-authz-req+jwt",
					},
				});
			},
			async () => {
				const request = await parseOpenid4VpAuthorizationUrl(
					"openid4vp://authorize?client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt",
				);

				expect(request.client_id).toBe("x509_san_dns:verifier.example");
				expect(request.nonce).toBe("nonce-123");
			},
		);
	});

	test("rejects request_uri when hostname does not match client_id", async () => {
		await expect(
			parseOpenid4VpAuthorizationUrl(
				"openid4vp://authorize?client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fother.example%2Frequest.jwt",
			),
		).rejects.toThrow("request_uri hostname must match client_id hostname");
	});

	test("rejects non-https request_uri", async () => {
		await expect(
			parseOpenid4VpAuthorizationUrl(
				"openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&request_uri=http%3A%2F%2Fverifier.example%2Frequest.jwt",
			),
		).rejects.toThrow("request_uri must use https");
	});

	test("rejects request_uri response with wrong content type", async () => {
		await withMockedFetch(
			async () =>
				new Response("bad", {
					status: 200,
					headers: { "content-type": "application/jwt" },
				}),
			async () => {
				await expect(
					parseOpenid4VpAuthorizationUrl(
						"openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt",
					),
				).rejects.toThrow(
					"request_uri response must use content-type application/oauth-authz-req+jwt",
				);
			},
		);
	});

	test("rejects request_uri combined with inline dcql_query", async () => {
		await expect(
			parseOpenid4VpAuthorizationUrl(
				`openid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&request_uri=${encodeURIComponent("https://verifier.example/request.jwt")}&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [] }))}`,
			),
		).rejects.toThrow(
			"Inline dcql_query cannot be combined with request or request_uri",
		);
	});

	test("rejects request objects with invalid typ header", async () => {
		const { privateKey } = await generateKeyPair("ES256");
		const requestObject = await new SignJWT({
			client_id: "https://verifier.example",
			nonce: "nonce-123",
			dcql_query: { credentials: [] },
		})
			.setProtectedHeader({ alg: "ES256", typ: "JWT" })
			.sign(privateKey);

		await expect(
			resolveOpenId4VpRequest({
				client_id: "https://verifier.example",
				request: requestObject,
			}),
		).rejects.toThrow(
			"Request object must be a valid JWT with typ=oauth-authz-req+jwt",
		);
	});

	test("rejects invalid request_uri_method values", async () => {
		await expect(
			parseOpenid4VpAuthorizationUrl(
				"openid4vp://authorize?client_id=https%3A%2F%2Fverifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt&request_uri_method=put",
			),
		).rejects.toThrow("invalid_request_uri_method");
	});

	test("submits a direct_post authorization response", async () => {
		await withMockedFetch(
			async (input, init) => {
				expect(String(input)).toBe("https://verifier.example/response");
				expect(init?.method).toBe("POST");
				expect(init?.headers).toEqual({
					"content-type": "application/x-www-form-urlencoded",
				});
				const body = String(init?.body);
				expect(body).toContain("vp_token=vp-token-123");
				expect(body).toContain("state=state-123");
				return new Response(
					JSON.stringify({ redirect_uri: "https://verifier.example/done" }),
					{
						status: 200,
						headers: { "content-type": "application/json" },
					},
				);
			},
			async () => {
				const result = await submitOpenId4VpAuthorizationResponse(
					{
						client_id: "https://verifier.example",
						nonce: "nonce-123",
						state: "state-123",
						response_mode: "direct_post",
						response_uri: "https://verifier.example/response",
						dcql_query: { credentials: [] },
					},
					{ vp_token: "vp-token-123", state: "state-123" },
				);

				expect(result.status).toBe(200);
				expect(result.redirectUri).toBe("https://verifier.example/done");
			},
		);
	});

	test("submits a direct_post.jwt authorization response", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RSA-OAEP-256", {
			modulusLength: 2048,
			extractable: true,
		});
		const publicJwk = await exportJWK(publicKey);

		await withMockedFetch(
			async (_input, init) => {
				const params = new URLSearchParams(String(init?.body));
				const encrypted = params.get("response");
				if (!encrypted) {
					throw new Error("Expected encrypted response");
				}

				const decrypted = await jwtDecrypt(encrypted, privateKey, {
					audience: "https://verifier.example",
				});
				expect(decrypted.payload.vp_token).toBe("vp-token-123");
				expect(decrypted.payload.state).toBe("state-123");
				return new Response(JSON.stringify({ ok: true }), {
					status: 200,
					headers: { "content-type": "application/json" },
				});
			},
			async () => {
				const result = await submitOpenId4VpAuthorizationResponse(
					{
						client_id: "https://verifier.example",
						nonce: "nonce-123",
						state: "state-123",
						response_mode: "direct_post.jwt",
						response_uri: "https://verifier.example/response",
						client_metadata: {
							jwks: { keys: [publicJwk as Record<string, unknown>] },
						},
						dcql_query: { credentials: [] },
					},
					{ vp_token: "vp-token-123", state: "state-123" },
				);

				expect(result.status).toBe(200);
				expect(result.responseMode).toBe("direct_post.jwt");
			},
		);
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

	test("creates an authorization response from a presentation", async () => {
		const response = createOpenId4VpAuthorizationResponse(
			{
				client_id: "https://verifier.example",
				nonce: "nonce-123",
				state: "state-123",
				dcql_query: { credentials: [] },
			},
			{
				query: { credentials: [] } as never,
				vpToken: "vp-token-123",
				dcqlPresentation: {},
				matchedCredentials: [],
			},
		);

		expect(response).toEqual({
			vp_token: "vp-token-123",
			state: "state-123",
		});
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
