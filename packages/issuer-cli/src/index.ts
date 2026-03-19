#!/usr/bin/env bun

import { handleCliError } from "./errors.ts";
import { createProgram } from "./program.ts";

export { createGrantAction } from "./actions/create-grant.ts";
export { createOfferAction } from "./actions/create-offer.ts";
export { generateTrustMaterialAction } from "./actions/generate-trust-material.ts";
export { issueCredentialAction } from "./actions/issue.ts";
export { metadataAction } from "./actions/metadata.ts";
export { nonceAction } from "./actions/nonce.ts";
export { createProgram };

export async function runCli(argv = process.argv): Promise<void> {
	try {
		await createProgram().parseAsync(argv);
	} catch (error) {
		handleCliError(error);
	}
}

if (import.meta.main) {
	await runCli();
}
