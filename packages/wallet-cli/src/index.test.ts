import { describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair } from "jose";
import {
	issueDemoCredential,
	type QueryCredentialMatches,
	Wallet,
} from "wallet";
import {
	importCredentialAction,
	initWalletAction,
	presentCredentialAction,
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
