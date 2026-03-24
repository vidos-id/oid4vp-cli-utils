import { execFileSync } from "node:child_process";
import {
	writeFile as fsWriteFile,
	mkdtemp,
	readFile,
	rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verbose, writeOptionalFile } from "cli-common";
import type { SigningAlg } from "issuer";
import { jwkSchema, signingAlgSchema } from "issuer";
import type { JWK } from "jose";
import {
	calculateJwkThumbprint,
	exportJWK,
	exportPKCS8,
	exportSPKI,
	importJWK,
	importPKCS8,
} from "jose";
import { resolveIssuerDirPaths } from "../paths.ts";
import { importTrustMaterialOptionsSchema } from "../schemas.ts";

function detectAlgFromJwk(jwk: Record<string, unknown>): SigningAlg {
	if (jwk.alg) {
		return signingAlgSchema.parse(jwk.alg);
	}
	const kty = jwk.kty as string | undefined;
	const crv = jwk.crv as string | undefined;
	if (kty === "EC" && crv === "P-384") {
		return "ES384";
	}
	if (kty === "EC") {
		return "ES256";
	}
	if (kty === "OKP") {
		return "EdDSA";
	}
	throw new Error("Cannot infer algorithm from key. Use --alg to specify.");
}

function certificatePemToX5c(certificatePem: string): string[] {
	return [
		certificatePem
			.replace("-----BEGIN CERTIFICATE-----", "")
			.replace("-----END CERTIFICATE-----", "")
			.replace(/\s+/g, ""),
	];
}

function cleanupFingerprint(value: string): string {
	return value
		.replace(/^sha256 fingerprint=/i, "")
		.replaceAll(":", "")
		.trim();
}

async function generateSelfSignedCert(privateKeyPem: string): Promise<{
	certificatePem: string;
	certificateFingerprintSha256: string;
}> {
	const dir = await mkdtemp(join(tmpdir(), "issuer-import-"));
	const keyPath = join(dir, "key.pem");
	const certPath = join(dir, "cert.pem");
	try {
		await fsWriteFile(keyPath, privateKeyPem, "utf8");
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
				"/CN=Imported Issuer/O=oid4vp-cli-utils",
				"-days",
				"365",
			],
			{ stdio: "ignore" },
		);
		const certificatePem = await readFile(certPath, "utf8");
		const fingerprintOutput = execFileSync(
			"openssl",
			["x509", "-noout", "-fingerprint", "-sha256", "-in", certPath],
			{ encoding: "utf8" },
		);
		return {
			certificatePem,
			certificateFingerprintSha256: cleanupFingerprint(fingerprintOutput),
		};
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

async function readCertificate(certPath: string): Promise<{
	certificatePem: string;
	certificateFingerprintSha256: string;
}> {
	const certificatePem = await readFile(certPath, "utf8");
	const dir = await mkdtemp(join(tmpdir(), "issuer-import-cert-"));
	const tmpCertPath = join(dir, "cert.pem");
	try {
		await fsWriteFile(tmpCertPath, certificatePem, "utf8");
		const fingerprintOutput = execFileSync(
			"openssl",
			["x509", "-noout", "-fingerprint", "-sha256", "-in", tmpCertPath],
			{ encoding: "utf8" },
		);
		return {
			certificatePem,
			certificateFingerprintSha256: cleanupFingerprint(fingerprintOutput),
		};
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

async function importPrivateKeyFromPem(
	privateKeyPem: string,
	alg?: SigningAlg,
): Promise<{ cryptoKey: CryptoKey; alg: SigningAlg }> {
	if (alg) {
		return {
			cryptoKey: await importPKCS8(privateKeyPem, alg, { extractable: true }),
			alg,
		};
	}

	for (const candidateAlg of signingAlgSchema.options) {
		try {
			return {
				cryptoKey: await importPKCS8(privateKeyPem, candidateAlg, {
					extractable: true,
				}),
				alg: candidateAlg,
			};
		} catch {}
	}

	throw new Error("Cannot infer algorithm from PEM key. Use --alg to specify.");
}

export async function importTrustMaterialAction(rawOptions: unknown) {
	const options = importTrustMaterialOptionsSchema.parse(rawOptions);
	const paths = resolveIssuerDirPaths(options.issuerDir);
	const keyContent = await readFile(options.privateKey, "utf8");
	const isPem = keyContent.trimStart().startsWith("-----BEGIN");

	let privateJwk: JWK;
	let publicJwk: JWK;
	let alg: SigningAlg;
	let privateKeyPem: string;
	let publicKeyPem: string;

	if (isPem) {
		const imported = await importPrivateKeyFromPem(keyContent, options.alg);
		alg = imported.alg;
		verbose(`Importing PEM private key with algorithm: ${alg}`);
		privateJwk = await exportJWK(imported.cryptoKey as CryptoKey);
		privateKeyPem = keyContent;

		const publicKey = await importJWK(
			{ ...privateJwk, d: undefined } as JWK,
			alg,
			{ extractable: true },
		);
		publicJwk = await exportJWK(publicKey as CryptoKey);
		publicKeyPem = await exportSPKI(publicKey as CryptoKey);
	} else {
		const rawJwk = JSON.parse(keyContent) as Record<string, unknown>;
		alg = options.alg ?? detectAlgFromJwk(rawJwk);
		verbose(`Importing JWK private key with algorithm: ${alg}`);

		const privateKey = await importJWK(rawJwk as JWK, alg, {
			extractable: true,
		});
		privateJwk = await exportJWK(privateKey as CryptoKey);
		privateKeyPem = await exportPKCS8(privateKey as CryptoKey);

		const publicKey = await importJWK(
			{ ...privateJwk, d: undefined } as JWK,
			alg,
			{ extractable: true },
		);
		publicJwk = await exportJWK(publicKey as CryptoKey);
		publicKeyPem = await exportSPKI(publicKey as CryptoKey);
	}

	const kid =
		typeof privateJwk.kid === "string"
			? privateJwk.kid
			: await calculateJwkThumbprint(publicJwk);

	privateJwk = jwkSchema.parse({ ...privateJwk, kid, alg, use: "sig" }) as JWK;
	publicJwk = jwkSchema.parse({ ...publicJwk, kid, alg, use: "sig" }) as JWK;

	const { certificatePem, certificateFingerprintSha256 } = options.certificate
		? await readCertificate(options.certificate)
		: await generateSelfSignedCert(privateKeyPem);

	const publicJwkWithCert = jwkSchema.parse({
		...publicJwk,
		x5c: certificatePemToX5c(certificatePem),
	}) as JWK;
	const jwks = { keys: [publicJwkWithCert] as [JWK] };

	const trustArtifact = {
		kid,
		alg,
		jwks,
		publicKeyPem,
		certificatePem,
		certificateFingerprintSha256,
	};

	await Promise.all([
		writeOptionalFile(paths.signingKeyFile, {
			alg,
			privateJwk,
			publicJwk: publicJwkWithCert,
		}),
		writeOptionalFile(paths.jwksFile, jwks),
		writeOptionalFile(paths.trustFile, trustArtifact),
	]);

	verbose(`Imported trust material to ${options.issuerDir}`);

	return {
		alg,
		kid,
		privateJwk,
		publicJwk: publicJwkWithCert,
		privateKeyPem,
		publicKeyPem,
		certificatePem,
		certificateFingerprintSha256,
		jwks,
		trustArtifact,
	};
}
