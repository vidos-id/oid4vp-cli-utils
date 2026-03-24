import { readFile } from "node:fs/promises";
import { Wallet } from "wallet";
import { initOptionsSchema } from "../schemas.ts";
import { FileSystemWalletStorage } from "../storage.ts";

export async function initWalletAction(rawOptions: unknown) {
	const options = initOptionsSchema.parse(rawOptions);
	const wallet = new Wallet(new FileSystemWalletStorage(options.walletDir));

	if (options.holderKeyFile) {
		const raw = JSON.parse(
			await readFile(options.holderKeyFile, "utf8"),
		) as Record<string, unknown>;
		const privateJwk = (raw.privateJwk ?? raw) as Record<string, unknown>;
		const publicJwk = (raw.publicJwk ?? raw) as Record<string, unknown>;
		const algorithm = detectAlgorithm(publicJwk, options.alg);
		const holderKey = await wallet.importHolderKey({
			privateJwk,
			publicJwk,
			algorithm,
		});
		return { holderKey };
	}

	const holderKey = await wallet.getOrCreateHolderKey(options.alg);
	return { holderKey };
}

function detectAlgorithm(
	jwk: Record<string, unknown>,
	explicit?: string,
): string {
	if (explicit) return explicit;
	const kty = jwk.kty as string;
	const crv = jwk.crv as string | undefined;
	if (kty === "EC" && crv === "P-384") return "ES384";
	if (kty === "EC") return "ES256";
	if (kty === "OKP") return "EdDSA";
	throw new Error(
		"Cannot infer algorithm from key type. Use --alg to specify.",
	);
}
