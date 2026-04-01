import { describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	issueDemoCredential,
	type QueryCredentialMatches,
	Wallet,
} from "@vidos-id/wallet";
import inquirer from "inquirer";
import { exportJWK, generateKeyPair } from "jose";
import {
	type AccessTokenRecord,
	createIssuer,
	generateIssuerTrustMaterial,
	jwkSchema,
	type NonceRecord,
	type PreAuthorizedGrantRecord,
} from "../../issuer/src/index.ts";
import { runInteractiveChoice } from "./actions/interactive.ts";
import {
	createProgram,
	deleteAllCredentialsAction,
	deleteCredentialAction,
	deleteWalletAction,
	importCredentialAction,
	initWalletAction,
	interactiveWalletAction,
	parseInteractiveCliOptions,
	presentCredentialAction,
	receiveCredentialAction,
	showCredentialAction,
} from "./index.ts";
import { FileSystemWalletStorage } from "./storage.ts";

async function seedTwoCredentials(walletDir: string) {
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

	const importedA = await importCredentialAction({
		walletDir,
		credential: credentialA,
	});
	const importedB = await importCredentialAction({
		walletDir,
		credential: credentialB,
	});

	return {
		storage,
		credentials: [importedA.credential, importedB.credential],
	};
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
			expect(result.imported).toBe(false);
			expect(await readdir(walletDir)).toContain("holder-key.json");
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("subcommands still parse --wallet-dir", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-program-init-"));
		try {
			await createProgram("0.0.0").parseAsync([
				"bun",
				"wallet-cli",
				"init",
				"--wallet-dir",
				walletDir,
			]);
			expect(await readdir(walletDir)).toContain("holder-key.json");
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("parses interactive wallet-dir from argv", () => {
		expect(
			parseInteractiveCliOptions([
				"bun",
				"wallet-cli",
				"--wallet-dir",
				"./wallet-data",
				"--verbose",
			]),
		).toEqual({ walletDir: "./wallet-data", verbose: true });
		expect(
			parseInteractiveCliOptions([
				"bun",
				"wallet-cli",
				"--wallet-dir=./wallet-data",
			]),
		).toEqual({ walletDir: "./wallet-data" });
	});

	test("interactive action cancellation does not throw for missing wallet", async () => {
		const writes: string[] = [];
		const originalWrite = process.stdout.write.bind(process.stdout);
		process.stdout.write = ((chunk: string | Uint8Array) => {
			writes.push(String(chunk));
			return true;
		}) as typeof process.stdout.write;
		try {
			const walletDir = join(tmpdir(), "wallet-cli-missing-wallet");
			const prompt = {
				confirm: async () => false,
				text: async () => "",
				choose: async () => "ES256",
			} as unknown as Parameters<typeof runInteractiveChoice>[0]["prompt"];

			await expect(
				runInteractiveChoice({
					prompt,
					walletDir,
					choice: "list",
				}),
			).resolves.toBe(walletDir);
			expect(writes.join("")).toContain("Action cancelled.");
		} finally {
			process.stdout.write = originalWrite;
		}
	});

	test("deletes an individual credential", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-delete-one-"));
		try {
			const { storage, credentials } = await seedTwoCredentials(walletDir);

			await deleteCredentialAction({
				walletDir,
				credentialId: credentials[0]!.id,
			});

			expect(await storage.getCredential(credentials[0]!.id)).toBeNull();
			expect(await storage.listCredentials()).toHaveLength(1);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("deletes all credentials", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-delete-all-"));
		try {
			const { storage } = await seedTwoCredentials(walletDir);

			await expect(deleteAllCredentialsAction({ walletDir })).resolves.toEqual({
				deleted: 2,
			});

			expect(await storage.listCredentials()).toHaveLength(0);
			expect(await readdir(join(walletDir, "credentials"))).toHaveLength(0);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("delete wallet interactive choice removes wallet and exits", async () => {
		const walletDir = await mkdtemp(
			join(tmpdir(), "wallet-cli-delete-wallet-"),
		);
		try {
			await initWalletAction({ walletDir });
			const prompt = {
				confirm: async () => true,
				text: async () => "",
				choose: async () => "ES256",
			} as unknown as Parameters<typeof runInteractiveChoice>[0]["prompt"];

			await expect(
				runInteractiveChoice({
					prompt,
					walletDir,
					choice: "delete-wallet",
				}),
			).resolves.toBeUndefined();

			await expect(readdir(walletDir)).rejects.toMatchObject({
				code: "ENOENT",
			});
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("delete wallet action removes wallet directory", async () => {
		const walletDir = await mkdtemp(
			join(tmpdir(), "wallet-cli-delete-wallet-action-"),
		);
		try {
			await initWalletAction({ walletDir });
			await deleteWalletAction({ walletDir });
			await expect(readdir(walletDir)).rejects.toMatchObject({
				code: "ENOENT",
			});
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

	test("show returns warning instead of failing when status resolution fails", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-show-warning-"));
		try {
			const issuer = await createOid4VciIssuerFixture();
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
							status: {
								status_list: {
									uri: "https://issuer.example/status-lists/missing",
									idx: 7,
								},
							},
						});
						currentAccessToken = issued.updatedAccessToken;
						return Response.json(issued);
					}
					if (url === "https://issuer.example/status-lists/missing") {
						return new Response("nope", { status: 500 });
					}
					throw new Error(`Unexpected fetch ${url}`);
				},
				async () => {
					const received = await receiveCredentialAction({
						walletDir,
						offer: JSON.stringify(offer),
					});
					const shown = await showCredentialAction({
						walletDir,
						credentialId: received.credential.id,
					});
					expect(shown.status).toBeNull();
					expect(shown.statusWarning).toContain(
						"Status list fetch failed with status 500",
					);
					if (!shown.credential.status?.status_list) {
						throw new Error("Expected stored credential status reference");
					}
					expect(shown.credential.status.status_list.uri).toBe(
						"https://issuer.example/status-lists/missing",
					);
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

	test("accepts a quoted openid4vp authorization URL", async () => {
		const walletDir = await mkdtemp(
			join(tmpdir(), "wallet-cli-openid4vp-quoted-"),
		);
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

			const url = `openid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&nonce=nonce-1&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [{ id: "person_credential", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/PersonCredential"] }, claims: [{ path: ["given_name"] }] }] }))}`;
			const result = await presentCredentialAction({
				walletDir,
				request: `"${url}"`,
			});

			expect(result.matchedCredentials[0]?.vct).toBe(
				"https://example.com/PersonCredential",
			);
			expect(result.vpToken.length).toBeGreaterThan(0);
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("interactive mode keeps running after presentation errors", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-interactive-"));
		const originalPrompt = inquirer.prompt;
		const originalStdoutWrite = process.stdout.write.bind(process.stdout);
		const originalStderrWrite = process.stderr.write.bind(process.stderr);
		const stdinDescriptor = Object.getOwnPropertyDescriptor(
			process.stdin,
			"isTTY",
		);
		const stdoutDescriptor = Object.getOwnPropertyDescriptor(
			process.stdout,
			"isTTY",
		);
		const stderrWrites: string[] = [];
		const answers = [
			{ value: walletDir },
			{ value: "present" },
			{
				value: JSON.stringify({
					client_id: "https://verifier.example",
					nonce: "nonce-1",
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
			},
			{ value: "exit" },
		];
		try {
			await initWalletAction({ walletDir });
			Object.defineProperty(process.stdin, "isTTY", {
				configurable: true,
				value: true,
			});
			Object.defineProperty(process.stdout, "isTTY", {
				configurable: true,
				value: true,
			});
			inquirer.prompt = (async () => {
				const answer = answers.shift();
				if (!answer) {
					throw new Error("Unexpected prompt");
				}
				return answer;
			}) as unknown as typeof inquirer.prompt;
			process.stdout.write = (() => true) as typeof process.stdout.write;
			process.stderr.write = ((chunk: string | Uint8Array) => {
				stderrWrites.push(String(chunk));
				return true;
			}) as typeof process.stderr.write;

			await expect(interactiveWalletAction({})).resolves.toBeUndefined();
			expect(stderrWrites.join("")).toContain(
				"No stored credential satisfies the supported DCQL query",
			);
		} finally {
			inquirer.prompt = originalPrompt;
			process.stdout.write = originalStdoutWrite;
			process.stderr.write = originalStderrWrite;
			if (stdinDescriptor) {
				Object.defineProperty(process.stdin, "isTTY", stdinDescriptor);
			}
			if (stdoutDescriptor) {
				Object.defineProperty(process.stdout, "isTTY", stdoutDescriptor);
			}
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
