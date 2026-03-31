import { describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	issueDemoCredential,
	type QueryCredentialMatches,
	Wallet,
} from "@vidos-id/wallet";
import { exportJWK, generateKeyPair } from "jose";
import {
	type AccessTokenRecord,
	createIssuer,
	generateIssuerTrustMaterial,
	jwkSchema,
	type NonceRecord,
	type PreAuthorizedGrantRecord,
} from "../../issuer/src/index.ts";
import {
	importCredentialAction,
	initWalletAction,
	presentCredentialAction,
	receiveCredentialAction,
	showCredentialAction,
} from "./index.ts";
import { FileSystemWalletStorage } from "./storage.ts";

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

describe("wallet-cli", () => {
	test("persists holder key and credentials as separate files", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-"));
		try {
			const storage = new FileSystemWalletStorage(walletDir);
			const wallet = new Wallet(storage);
			const issuer = await createIssuerFixture();
			const holderKey = await wallet.getOrCreateHolderKey();

			const credentialA = await issueDemoCredential({
				issuer: issuer.issuer,
				issuerPrivateJwk: issuer.privateJwk,
				holderPublicJwk: holderKey.publicJwk as never,
				vct: "https://example.com/A",
				claims: { given_name: "Ada" },
				disclosureFrame: { _sd: ["given_name"] },
				issuedAt: 1,
			});
			const credentialB = await issueDemoCredential({
				issuer: issuer.issuer,
				issuerPrivateJwk: issuer.privateJwk,
				holderPublicJwk: holderKey.publicJwk as never,
				vct: "https://example.com/B",
				claims: { family_name: "Lovelace" },
				disclosureFrame: { _sd: ["family_name"] },
				issuedAt: 1,
			});

			await importCredentialAction({
				walletDir,
				credential: credentialA,
			});
			await importCredentialAction({
				walletDir,
				credential: credentialB,
			});

			const files = await readdir(join(walletDir, "credentials"));
			expect(files).toHaveLength(2);
			expect(await readdir(walletDir)).toContain("holder-key.json");
			expect(await readdir(walletDir)).toContain("wallet.json");

			const reopened = new FileSystemWalletStorage(walletDir);
			expect(await reopened.getHolderKey()).not.toBeNull();
			expect(await reopened.listCredentials()).toHaveLength(2);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("init creates holder key before issuance", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-init-"));
		try {
			const result = await initWalletAction({ walletDir });
			expect(result.holderKey.id.length).toBeGreaterThan(0);
			expect(await readdir(walletDir)).toContain("holder-key.json");
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("receives and stores a credential from an OID4VCI offer", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-receive-"));
		try {
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
						url ===
						"https://issuer.example/.well-known/openid-credential-issuer"
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
					const result = await receiveCredentialAction({
						walletDir,
						offer: JSON.stringify(offer),
					});
					expect(result.credential.issuer).toBe("https://issuer.example");
					expect(result.credential.claims).toEqual({
						given_name: "Ada",
						family_name: "Lovelace",
					});
					const shown = await showCredentialAction({
						walletDir,
						credentialId: result.credential.id,
						resolveStatus: true,
					});
					expect(shown.status?.status).toEqual({
						value: 0,
						label: "VALID",
						isValid: true,
					});
					currentStatusList = issuer.updateCredentialStatus({
						statusList: currentStatusList,
						idx: 0,
						status: 2,
					});
					const suspended = await showCredentialAction({
						walletDir,
						credentialId: result.credential.id,
						resolveStatus: true,
					});
					expect(suspended.status?.status).toEqual({
						value: 2,
						label: "SUSPENDED",
						isValid: false,
					});
				},
			);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("receives and stores a credential from a credential_offer_uri", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-receive-ref-"));
		try {
			const issuer = await createOid4VciIssuerFixture();
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
						url ===
						"https://issuer.example/.well-known/openid-credential-issuer"
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
						});
						currentAccessToken = issued.updatedAccessToken;
						return Response.json(issued);
					}
					throw new Error(`Unexpected fetch ${url}`);
				},
				async () => {
					const result = await receiveCredentialAction({
						walletDir,
						offer: offerReference,
					});
					expect(result.credential.issuer).toBe("https://issuer.example");
					expect(result.credential.claims).toEqual({
						given_name: "Ada",
						family_name: "Lovelace",
					});
				},
			);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("rejects presentation exchange input", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-request-"));
		try {
			await expect(
				presentCredentialAction({
					walletDir,
					request: JSON.stringify({
						client_id: "https://verifier.example",
						nonce: "nonce-1",
						presentation_definition: { id: "pd-1", input_descriptors: [] },
					}),
				}),
			).rejects.toThrow("Presentation Exchange is unsupported");
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("accepts an openid4vp authorization URL", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-openid4vp-"));
		try {
			const storage = new FileSystemWalletStorage(walletDir);
			const wallet = new Wallet(storage);
			const issuer = await createIssuerFixture();
			const holderKey = await wallet.getOrCreateHolderKey();

			const credential = await issueDemoCredential({
				issuer: issuer.issuer,
				issuerPrivateJwk: issuer.privateJwk,
				holderPublicJwk: holderKey.publicJwk as never,
				vct: "https://example.com/PersonCredential",
				claims: { given_name: "Ada" },
				disclosureFrame: { _sd: ["given_name"] },
				issuedAt: 1,
			});

			await importCredentialAction({
				walletDir,
				credential,
			});

			const result = await presentCredentialAction({
				walletDir,
				request: `openid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&nonce=nonce-1&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [{ id: "person_credential", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/PersonCredential"] }, claims: [{ path: ["given_name"] }] }] }))}`,
			});

			expect(result.matchedCredentials[0]?.vct).toBe(
				"https://example.com/PersonCredential",
			);
			expect(result.vpToken.length).toBeGreaterThan(0);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("prompts for credential selection when multiple credentials match", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-select-"));
		try {
			const storage = new FileSystemWalletStorage(walletDir);
			const wallet = new Wallet(storage);
			const issuer = await createIssuerFixture();
			const holderKey = await wallet.getOrCreateHolderKey();

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

			const importedAda = await importCredentialAction({
				walletDir,
				credential: credentialAda,
			});
			const importedGrace = await importCredentialAction({
				walletDir,
				credential: credentialGrace,
			});

			const result = await presentCredentialAction({
				walletDir,
				request: JSON.stringify({
					client_id: "https://verifier.example",
					nonce: "nonce-2",
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
				}),
				prompt: async (queryMatch: QueryCredentialMatches) => {
					expect(
						queryMatch.credentials.map((item) => item.credentialId),
					).toEqual([importedAda.credential.id, importedGrace.credential.id]);
					return importedGrace.credential.id;
				},
			});

			expect(result.matchedCredentials[0]?.credentialId).toBe(
				importedGrace.credential.id,
			);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("auto-submits direct_post unless dry-run is set", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-submit-"));
		try {
			const storage = new FileSystemWalletStorage(walletDir);
			const wallet = new Wallet(storage);
			const issuer = await createIssuerFixture();
			const holderKey = await wallet.getOrCreateHolderKey();

			const credential = await issueDemoCredential({
				issuer: issuer.issuer,
				issuerPrivateJwk: issuer.privateJwk,
				holderPublicJwk: holderKey.publicJwk as never,
				vct: "https://example.com/PersonCredential",
				claims: { given_name: "Ada" },
				disclosureFrame: { _sd: ["given_name"] },
				issuedAt: 1,
			});

			await importCredentialAction({
				walletDir,
				credential,
			});

			let postCount = 0;
			await withMockedFetch(
				async (_input, init) => {
					postCount += 1;
					expect(init?.method).toBe("POST");
					return new Response(JSON.stringify({ ok: true }), {
						status: 200,
						headers: { "content-type": "application/json" },
					});
				},
				async () => {
					const request = JSON.stringify({
						client_id: "https://verifier.example",
						nonce: "nonce-1",
						response_mode: "direct_post",
						response_uri: "https://verifier.example/response",
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

					const submitted = await presentCredentialAction({
						walletDir,
						request,
					});
					expect(submitted.submitted).toBe(true);

					const dryRun = await presentCredentialAction({
						walletDir,
						request,
						dryRun: true,
					});
					expect(dryRun.submitted).toBe(false);
				},
			);

			expect(postCount).toBe(1);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});
});
