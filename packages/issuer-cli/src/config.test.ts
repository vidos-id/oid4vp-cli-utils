import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveIssuerConfig } from "./config.ts";

describe("resolveIssuerConfig", () => {
	test("rejects verifier trust material passed as signing key file", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "issuer-cli-config-"));
		try {
			const trustPath = join(tempDir, "trust.json");
			await writeFile(
				trustPath,
				JSON.stringify({
					kid: "issuer-key-1",
					alg: "EdDSA",
					jwks: {
						keys: [{ kty: "OKP", crv: "Ed25519", x: "x", kid: "issuer-key-1" }],
					},
					publicKeyPem: "pem",
					certificatePem: "cert",
					certificateFingerprintSha256: "fingerprint",
				}),
				"utf8",
			);

			await expect(
				resolveIssuerConfig({
					issuer: "https://issuer.example",
					signingKeyFile: trustPath,
					vct: "https://example.com/PersonCredential",
				}),
			).rejects.toThrow("looks like verifier trust material");
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});
});
