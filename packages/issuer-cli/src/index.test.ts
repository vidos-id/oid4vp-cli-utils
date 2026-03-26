import { describe, expect, test } from "bun:test";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateIssuerTrustMaterial } from "@vidos-id/issuer";
import { initWalletAction } from "../../wallet-cli/src/index.ts";
import { issueCredentialAction } from "./index.ts";

describe("issuer-cli", () => {
	test("issues a credential from claims without explicit proof input", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "issuer-cli-"));
		try {
			const trust = await generateIssuerTrustMaterial({ kid: "issuer-key-1" });
			await writeFile(
				join(tempDir, "signing-key.json"),
				JSON.stringify({
					alg: trust.alg,
					privateJwk: trust.privateJwk,
					publicJwk: trust.publicJwk,
				}),
				"utf8",
			);

			const result = await issueCredentialAction({
				issuer: "https://issuer.example",
				issuerDir: tempDir,
				vct: "https://example.com/PersonCredential",
				claims: JSON.stringify({ given_name: "Ada" }),
			});

			expect(result.format).toBe("dc+sd-jwt");
			expect(result.credential_configuration_id).toBe("credential");
			expect(result.access_token).toBeString();
			expect(result.c_nonce).toBeString();
			expect(result.credential).not.toContain('"cnf"');
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});

	test("issues from PID claims file that includes vct", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "issuer-cli-"));
		try {
			const trust = await generateIssuerTrustMaterial({ kid: "issuer-key-1" });
			await writeFile(
				join(tempDir, "signing-key.json"),
				JSON.stringify({
					alg: trust.alg,
					privateJwk: trust.privateJwk,
					publicJwk: trust.publicJwk,
				}),
				"utf8",
			);

			const result = await issueCredentialAction({
				issuer: "https://issuer.example",
				issuerDir: tempDir,
				vct: "urn:eudi:pid:1",
				claimsFile: "examples/pid/pid-minimal.claims.json",
			});

			expect(result.format).toBe("dc+sd-jwt");
			expect(result.credential_configuration_id).toBe("credential");
			expect(result.access_token).toBeString();
			expect(result.c_nonce).toBeString();
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});

	test("issues holder-bound credential from holder key file and writes credential file", async () => {
		const issuerDir = await mkdtemp(join(tmpdir(), "issuer-cli-issuer-"));
		const walletDir = await mkdtemp(join(tmpdir(), "issuer-cli-wallet-"));
		try {
			const trust = await generateIssuerTrustMaterial({ kid: "issuer-key-1" });
			await writeFile(
				join(issuerDir, "signing-key.json"),
				JSON.stringify({
					alg: trust.alg,
					privateJwk: trust.privateJwk,
					publicJwk: trust.publicJwk,
				}),
				"utf8",
			);
			await initWalletAction({ walletDir });

			const result = await issueCredentialAction({
				issuer: "https://issuer.example",
				issuerDir,
				credentialFile: "my-credential.txt",
				holderKeyFile: join(walletDir, "holder-key.json"),
				vct: "https://example.com/PersonCredential",
				claims: JSON.stringify({ given_name: "Ada" }),
			});

			expect(result.format).toBe("dc+sd-jwt");
			expect(result.c_nonce).toBeString();
			const saved = await readFile(
				join(issuerDir, "my-credential.txt"),
				"utf8",
			);
			expect(saved.trim()).toBe(result.credential);
		} finally {
			await rm(issuerDir, { recursive: true, force: true });
			await rm(walletDir, { recursive: true, force: true });
		}
	});

	test("issues credential with auto-generated UUID filename when credentialFile not specified", async () => {
		const issuerDir = await mkdtemp(join(tmpdir(), "issuer-cli-issuer-"));
		try {
			const trust = await generateIssuerTrustMaterial({ kid: "issuer-key-1" });
			await writeFile(
				join(issuerDir, "signing-key.json"),
				JSON.stringify({
					alg: trust.alg,
					privateJwk: trust.privateJwk,
					publicJwk: trust.publicJwk,
				}),
				"utf8",
			);

			const result = await issueCredentialAction({
				issuer: "https://issuer.example",
				issuerDir,
				vct: "https://example.com/PersonCredential",
				claims: JSON.stringify({ given_name: "Ada" }),
			});

			expect(result.format).toBe("dc+sd-jwt");
			expect(result.c_nonce).toBeString();
			const files = await readdir(issuerDir);
			const credentialFile = files.find(
				(f: string) => f.startsWith("credential-") && f.endsWith(".txt"),
			);
			expect(credentialFile != null).toBe(true);
			const saved = await readFile(
				join(issuerDir, credentialFile as string),
				"utf8",
			);
			expect(saved.trim()).toBe(result.credential);
		} finally {
			await rm(issuerDir, { recursive: true, force: true });
		}
	});
});
