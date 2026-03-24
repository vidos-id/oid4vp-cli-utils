import { readTextInput } from "cli-common";
import { claimSetSchema } from "../schemas.ts";

export async function resolveClaims(claims?: string, claimsFile?: string) {
	const raw = await readTextInput(claims, claimsFile);
	return claimSetSchema.parse(JSON.parse(raw) as unknown);
}
