import { describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair } from "jose";
import {
	issueDemoCredential,
	type QueryCredentialMatches,
	Wallet,
} from "wallet";
import { importCredentialAction, presentCredentialAction } from "./index.ts";
import { FileSystemWalletStorage } from "./storage.ts";

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
				issuerMetadata: JSON.stringify({
					issuer: issuer.issuer,
					jwks: { keys: [issuer.publicJwk] },
				}),
			});
			await importCredentialAction({
				walletDir,
				credential: credentialB,
				issuerMetadata: JSON.stringify({
					issuer: issuer.issuer,
					jwks: { keys: [issuer.publicJwk] },
				}),
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

	test("rejects presentation exchange input", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-request-"));
		try {
			const requestPath = join(walletDir, "request.json");
			await writeFile(
				requestPath,
				JSON.stringify({
					client_id: "https://verifier.example",
					nonce: "nonce-1",
					presentation_definition: { id: "pd-1", input_descriptors: [] },
				}),
				"utf8",
			);

			await expect(
				presentCredentialAction({
					walletDir,
					requestFile: requestPath,
				}),
			).rejects.toThrow("Presentation Exchange is unsupported");
		} finally {
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("accepts an oid4vp authorization URL", async () => {
		const walletDir = await mkdtemp(join(tmpdir(), "wallet-cli-oid4vp-"));
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
				issuerMetadata: JSON.stringify({
					issuer: issuer.issuer,
					jwks: { keys: [issuer.publicJwk] },
				}),
			});

			const result = await presentCredentialAction({
				walletDir,
				request: `oid4vp://authorize?client_id=${encodeURIComponent("https://verifier.example")}&nonce=nonce-1&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify({ credentials: [{ id: "person_credential", format: "dc+sd-jwt", meta: { vct_values: ["https://example.com/PersonCredential"] }, claims: [{ path: ["given_name"] }] }] }))}`,
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
				issuerMetadata: JSON.stringify({
					issuer: issuer.issuer,
					jwks: { keys: [issuer.publicJwk] },
				}),
			});
			const importedGrace = await importCredentialAction({
				walletDir,
				credential: credentialGrace,
				issuerMetadata: JSON.stringify({
					issuer: issuer.issuer,
					jwks: { keys: [issuer.publicJwk] },
				}),
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
});
