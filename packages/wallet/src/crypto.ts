import { pack } from "@sd-jwt/core";
import { hasher as defaultSdJwtHasher } from "@sd-jwt/hash";
import type { JWK, JWTHeaderParameters } from "jose";
import {
	base64url,
	calculateJwkThumbprint,
	exportJWK,
	generateKeyPair,
	importJWK,
	SignJWT,
} from "jose";

import type { HolderKeyRecord } from "./schemas.ts";

export const HOLDER_KEY_ALG = "ES256";
export const SD_JWT_HASH_ALG = "sha-256";

type ImportedJwkKey = Awaited<ReturnType<typeof importJWK>>;

export async function sha256Base64Url(input: string): Promise<string> {
	const digest = defaultSdJwtHasher(input, "sha256");
	return base64url.encode(digest);
}

export async function sdJwtHasher(
	data: string | ArrayBuffer,
	alg: string,
): Promise<Uint8Array> {
	if (alg !== SD_JWT_HASH_ALG) {
		throw new Error(`Unsupported SD-JWT hash algorithm: ${alg}`);
	}

	return defaultSdJwtHasher(data, "sha256");
}

export async function createHolderKeyRecord(
	alg?: HolderKeyRecord["algorithm"],
): Promise<HolderKeyRecord> {
	const algorithm = alg ?? HOLDER_KEY_ALG;
	const { privateKey, publicKey } =
		algorithm === "EdDSA"
			? await generateKeyPair("EdDSA", {
					crv: "Ed25519",
					extractable: true,
				})
			: await generateKeyPair(algorithm, {
					extractable: true,
				});
	const publicJwk = await exportJWK(publicKey);
	const privateJwk = await exportJWK(privateKey);
	const id = await calculateJwkThumbprint(publicJwk);

	return {
		id,
		algorithm,
		publicJwk: publicJwk as Record<string, unknown>,
		privateJwk: privateJwk as Record<string, unknown>,
		createdAt: new Date().toISOString(),
	};
}

export async function getJwkThumbprint(jwk: JWK): Promise<string> {
	return calculateJwkThumbprint(jwk);
}

export async function importPrivateKey(
	jwk: JWK,
	alg: string = HOLDER_KEY_ALG,
): Promise<ImportedJwkKey> {
	return importJWK(jwk, alg);
}

export async function importPublicKey(
	jwk: JWK,
	alg: string,
): Promise<ImportedJwkKey> {
	return importJWK(jwk, alg);
}

export async function createKbJwt(input: {
	holderPrivateJwk: JWK;
	aud: string;
	nonce: string;
	sdJwtPresentation: string;
	alg?: string;
}): Promise<string> {
	const alg = input.alg ?? HOLDER_KEY_ALG;
	const privateKey = await importPrivateKey(input.holderPrivateJwk, alg);
	const sdHash = await sha256Base64Url(input.sdJwtPresentation);

	return new SignJWT({
		aud: input.aud,
		nonce: input.nonce,
		sd_hash: sdHash,
		iat: Math.floor(Date.now() / 1000),
	})
		.setProtectedHeader({ alg, typ: "kb+jwt" })
		.sign(privateKey);
}

export async function issueDemoCredential(input: {
	issuer: string;
	issuerPrivateJwk: JWK;
	issuerAlg?: string;
	issuerKid?: string;
	holderPublicJwk: JWK;
	vct: string;
	claims: Record<string, unknown>;
	disclosureFrame?: Record<string, unknown>;
	headers?: JWTHeaderParameters;
	issuedAt?: number;
	saltGenerator?: (length: number) => Promise<string>;
}): Promise<string> {
	const signingAlg = input.issuerAlg ?? HOLDER_KEY_ALG;
	const issuerKey = await importPrivateKey(input.issuerPrivateJwk, signingAlg);
	let saltIndex = 0;
	const saltGenerator =
		input.saltGenerator ??
		(async () => {
			saltIndex += 1;
			return `salt-${saltIndex}`;
		});

	const payload = {
		iss: input.issuer,
		vct: input.vct,
		cnf: { jwk: input.holderPublicJwk },
		...input.claims,
	};

	const { packedClaims, disclosures } = await pack(
		payload,
		input.disclosureFrame,
		{ alg: SD_JWT_HASH_ALG, hasher: sdJwtHasher },
		saltGenerator,
	);

	const jwt = await new SignJWT({
		...packedClaims,
		_sd_alg: input.disclosureFrame ? SD_JWT_HASH_ALG : undefined,
		iat: input.issuedAt ?? Math.floor(Date.now() / 1000),
	})
		.setProtectedHeader({
			alg: signingAlg,
			typ: "dc+sd-jwt",
			kid: input.issuerKid,
			...input.headers,
		})
		.sign(issuerKey);

	return [
		jwt,
		...disclosures.map((disclosure) => disclosure.encode()),
		"",
	].join("~");
}
