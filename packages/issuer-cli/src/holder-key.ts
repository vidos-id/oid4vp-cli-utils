import { readFile } from "node:fs/promises";
import { jwkSchema } from "issuer";
import { z } from "zod";

const holderKeyFileSchema = z.object({
	publicJwk: jwkSchema,
});

export async function readHolderPublicJwk(filePath: string) {
	const parsed = holderKeyFileSchema.parse(
		JSON.parse(await readFile(filePath, "utf8")) as unknown,
	);
	return parsed.publicJwk;
}

export function parseHolderPublicJwk(json: string) {
	const raw = JSON.parse(json) as unknown;
	const asFile = holderKeyFileSchema.safeParse(raw);
	if (asFile.success) {
		return asFile.data.publicJwk;
	}
	return jwkSchema.parse(raw);
}
