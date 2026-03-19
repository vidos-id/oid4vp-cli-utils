import { readTextInput } from "../io.ts";
import { claimSetSchema, proofObjectSchema } from "../schemas.ts";

export async function resolveClaims(claims?: string, claimsFile?: string) {
	const raw = await readTextInput(claims, claimsFile);
	return claimSetSchema.parse(JSON.parse(raw) as unknown);
}

export async function resolveProof(proof?: string, proofFile?: string) {
	const raw = await readTextInput(proof, proofFile);
	const trimmed = raw.trim();
	if (trimmed.startsWith("{")) {
		return proofObjectSchema.parse(JSON.parse(trimmed) as unknown);
	}
	return proofObjectSchema.parse({ proof_type: "jwt", jwt: trimmed });
}

export function extractJwtNonce(jwt: string): string {
	const [, payload] = jwt.split(".");
	if (!payload) {
		throw new Error("Proof JWT payload is missing");
	}
	const decoded = JSON.parse(
		Buffer.from(payload, "base64url").toString("utf8"),
	) as { nonce?: unknown };
	if (typeof decoded.nonce !== "string" || decoded.nonce.length === 0) {
		throw new Error("Proof JWT payload nonce is missing");
	}
	return decoded.nonce;
}
