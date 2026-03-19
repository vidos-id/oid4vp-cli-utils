import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateIssuerTrustMaterial } from "issuer";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { issueCredentialAction, nonceAction } from "./index.ts";

async function createProofJwt(aud: string, nonce: string) {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
		crv: "Ed25519",
		extractable: true,
	});
	const publicJwk = await exportJWK(publicKey);
	const jwt = await new SignJWT({ aud, nonce, iat: 1 })
		.setProtectedHeader({
			alg: "EdDSA",
			typ: "openid4vci-proof+jwt",
			jwk: publicJwk,
		})
		.sign(privateKey);
	return { jwt };
}

describe("issuer-cli", () => {
	test("issues a credential from claims and proof input", async () => {
		const tempDir = await mkdtemp(join(tmpdir(), "issuer-cli-"));
		try {
			const trust = await generateIssuerTrustMaterial({ kid: "issuer-key-1" });
			const signingKeyPath = join(tempDir, "signing-key.json");
			await writeFile(signingKeyPath, JSON.stringify(trust), "utf8");

			const nonce = await nonceAction({
				issuer: "https://issuer.example",
				signingKeyFile: signingKeyPath,
				vct: "https://example.com/PersonCredential",
			});
			const proof = await createProofJwt(
				"https://issuer.example",
				nonce.c_nonce,
			);

			const result = await issueCredentialAction({
				issuer: "https://issuer.example",
				signingKeyFile: signingKeyPath,
				vct: "https://example.com/PersonCredential",
				claims: JSON.stringify({ given_name: "Ada", family_name: "Lovelace" }),
				proof: proof.jwt,
			});

			expect(result.format).toBe("dc+sd-jwt");
			expect(result.credential_configuration_id).toBe("credential");
			expect(result.access_token).toBeString();
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});
});
