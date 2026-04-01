#!/usr/bin/env bun

import {
	handleCliError,
	resolveCliVersion,
	resolvePackageJsonPath,
	setVerbose,
} from "@vidos-id/cli-common";
import { interactiveWalletAction } from "./actions/interactive.ts";
import { createProgram } from "./program.ts";

export {
	deleteAllCredentialsAction,
	deleteCredentialAction,
	deleteWalletAction,
} from "./actions/delete.ts";
export { importCredentialAction } from "./actions/import.ts";
export { initWalletAction } from "./actions/init.ts";
export { interactiveWalletAction } from "./actions/interactive.ts";
export { listCredentialsAction } from "./actions/list.ts";
export { presentCredentialAction } from "./actions/present.ts";
export { receiveCredentialAction } from "./actions/receive.ts";
export { showCredentialAction } from "./actions/show.ts";
export { createProgram };

type InteractiveCliOptions = {
	walletDir?: string;
	verbose?: boolean;
};

export function parseInteractiveCliOptions(
	argv: string[],
): InteractiveCliOptions {
	const options: InteractiveCliOptions = {};
	for (let index = 2; index < argv.length; index += 1) {
		const arg = argv[index];
		if (!arg) {
			continue;
		}
		if (arg === "--") {
			break;
		}
		if (arg === "--verbose") {
			options.verbose = true;
			continue;
		}
		if (arg === "--wallet-dir") {
			const value = argv[index + 1];
			if (!value || value.startsWith("-")) {
				throw new Error("option '--wallet-dir <dir>' argument missing");
			}
			options.walletDir = value;
			index += 1;
			continue;
		}
		if (arg.startsWith("--wallet-dir=")) {
			options.walletDir = arg.slice("--wallet-dir=".length);
		}
	}
	return options;
}

function findFirstPositionalArg(argv: string[]): string | undefined {
	for (let index = 2; index < argv.length; index += 1) {
		const arg = argv[index];
		if (!arg) {
			continue;
		}
		if (arg === "--") {
			return argv[index + 1];
		}
		if (arg === "--wallet-dir") {
			index += 1;
			continue;
		}
		if (arg.startsWith("-")) {
			continue;
		}
		return arg;
	}
	return undefined;
}

export async function runCli(argv = process.argv): Promise<void> {
	const version = await resolveCliVersion(
		resolvePackageJsonPath(import.meta.url),
	);
	const program = createProgram(version);
	try {
		const firstPositionalArg = findFirstPositionalArg(argv);
		const commandNames = new Set(
			program.commands.map((command) => command.name()),
		);
		if (
			firstPositionalArg === undefined &&
			!argv.includes("--help") &&
			!argv.includes("-h") &&
			!argv.includes("--version") &&
			!argv.includes("-V")
		) {
			const interactiveOptions = parseInteractiveCliOptions(argv);
			if (interactiveOptions.verbose) {
				setVerbose(true);
			}
			await interactiveWalletAction(interactiveOptions);
			return;
		}
		if (
			firstPositionalArg !== undefined &&
			!commandNames.has(firstPositionalArg)
		) {
			await program.parseAsync(argv);
			return;
		}
		await program.parseAsync(argv);
	} catch (error) {
		handleCliError(error);
	}
}

if (import.meta.main) {
	await runCli();
}
