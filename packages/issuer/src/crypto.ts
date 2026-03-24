import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JWK } from "jose";
import { exportJWK, exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { jwkSchema } from "./schemas.ts";

export type GeneratedTrustMaterial = {
	alg: "ES256" | "ES384" | "EdDSA";
	kid: string;
	privateJwk: JWK;
	publicJwk: JWK;
	privateKeyPem: string;
	publicKeyPem: string;
	certificatePem: string;
	certificateFingerprintSha256: string;
	jwks: { keys: [JWK] };
	trustArtifact: {
		kid: string;
		alg: "ES256" | "ES384" | "EdDSA";
		jwks: { keys: [JWK] };
		publicKeyPem: string;
		certificatePem: string;
		certificateFingerprintSha256: string;
	};
};

const cleanupFingerprint = (value: string) =>
	value
		.replace(/^sha256 fingerprint=/i, "")
		.replaceAll(":", "")
		.trim();

const certificatePemToX5c = (certificatePem: string) => [
	certificatePem
		.replace("-----BEGIN CERTIFICATE-----", "")
		.replace("-----END CERTIFICATE-----", "")
		.replace(/\s+/g, ""),
];

export const generateIssuerTrustMaterial = async (input?: {
	kid?: string;
	subject?: string;
	daysValid?: number;
	alg?: "ES256" | "ES384" | "EdDSA";
}) => {
	const kid = input?.kid ?? "issuer-key-1";
	const subject = input?.subject ?? "/CN=Demo Issuer/O=oid4vp-cli-utils";
	const daysValid = input?.daysValid ?? 365;
	const alg = input?.alg ?? "EdDSA";
	const { privateKey, publicKey } =
		alg === "EdDSA"
			? await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true })
			: await generateKeyPair(alg, { extractable: true });
	const privateJwk = jwkSchema.parse({
		...(await exportJWK(privateKey)),
		kid,
		alg,
		use: "sig",
	});
	const publicJwk = jwkSchema.parse({
		...(await exportJWK(publicKey)),
		kid,
		alg,
		use: "sig",
	});
	const privateKeyPem = await exportPKCS8(privateKey);
	const publicKeyPem = await exportSPKI(publicKey);

	const dir = await mkdtemp(join(tmpdir(), "issuer-trust-"));
	const keyPath = join(dir, "issuer-key.pem");
	const certPath = join(dir, "issuer-cert.pem");

	try {
		await writeFile(keyPath, privateKeyPem, "utf8");
		execFileSync(
			"openssl",
			[
				"req",
				"-x509",
				"-new",
				"-key",
				keyPath,
				"-out",
				certPath,
				"-subj",
				subject,
				"-days",
				String(daysValid),
			],
			{ stdio: "ignore" },
		);
		const certificatePem = await readFile(certPath, "utf8");
		const fingerprintOutput = execFileSync(
			"openssl",
			["x509", "-noout", "-fingerprint", "-sha256", "-in", certPath],
			{ encoding: "utf8" },
		);
		const certificateFingerprintSha256 = cleanupFingerprint(fingerprintOutput);
		const x5c = certificatePemToX5c(certificatePem);
		const publicJwkWithCertificate = jwkSchema.parse({
			...publicJwk,
			x5c,
		});
		const jwks = { keys: [publicJwkWithCertificate as JWK] as [JWK] };

		return {
			alg: alg as typeof alg,
			kid,
			privateJwk: privateJwk as JWK,
			publicJwk: publicJwkWithCertificate as JWK,
			privateKeyPem,
			publicKeyPem,
			certificatePem,
			certificateFingerprintSha256,
			jwks,
			trustArtifact: {
				kid,
				alg: alg as typeof alg,
				jwks,
				publicKeyPem,
				certificatePem,
				certificateFingerprintSha256,
			},
		} satisfies GeneratedTrustMaterial;
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};
