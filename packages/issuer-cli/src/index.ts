#!/usr/bin/env bun

import {
	handleCliError,
	readPackageVersion,
	resolvePackageJsonPath,
} from "cli-common";
import { createProgram } from "./program.ts";

export { generateTrustMaterialAction } from "./actions/generate-trust-material.ts";
export { importTrustMaterialAction } from "./actions/import-trust-material.ts";
export { initIssuerAction } from "./actions/init.ts";
export { issueCredentialAction } from "./actions/issue.ts";
export { createProgram };

export async function runCli(argv = process.argv): Promise<void> {
	const version = await readPackageVersion(
		resolvePackageJsonPath(import.meta.url),
	);
	try {
		await createProgram(version).parseAsync(argv);
	} catch (error) {
		handleCliError(error);
	}
}

if (import.meta.main) {
	await runCli();
}
