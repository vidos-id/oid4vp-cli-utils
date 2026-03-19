#!/usr/bin/env bun

import { handleCliError } from "./errors.ts";
import { createProgram } from "./program.ts";

export { importCredentialAction } from "./actions/import.ts";
export { listCredentialsAction } from "./actions/list.ts";
export { presentCredentialAction } from "./actions/present.ts";
export { showCredentialAction } from "./actions/show.ts";
export { createProgram };

export async function runCli(argv = process.argv): Promise<void> {
	const program = createProgram();
	try {
		await program.parseAsync(argv);
	} catch (error) {
		handleCliError(error);
	}
}

if (import.meta.main) {
	await runCli();
}
