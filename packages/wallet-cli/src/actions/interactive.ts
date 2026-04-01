import { access } from "node:fs/promises";
import { stdout } from "node:process";
import {
	formatCredentialDetails,
	formatCredentialList,
	formatCredentialSummary,
	formatDeleteAllCredentialsSummary,
	formatDeleteCredentialSummary,
	formatDeleteWalletSummary,
	formatInitResult,
	formatPresentationSummary,
} from "../format.ts";
import { PromptSession } from "../prompts.ts";
import {
	deleteAllCredentialsAction,
	deleteCredentialAction,
	deleteWalletAction,
} from "./delete.ts";
import { chooseCredentialId } from "./delete-helpers.ts";
import { importCredentialAction } from "./import.ts";
import { initWalletAction } from "./init.ts";
import { listCredentialsAction } from "./list.ts";
import { presentCredentialAction } from "./present.ts";
import { receiveCredentialAction } from "./receive.ts";
import { showCredentialAction } from "./show.ts";

const interactiveChoices = [
	{ label: "Receive credential offer", value: "receive" },
	{ label: "List credentials", value: "list" },
	{ label: "Show credential", value: "show" },
	{ label: "Delete credential", value: "delete" },
	{ label: "Delete all credentials", value: "delete-all" },
	{ label: "Present credential", value: "present" },
	{ label: "Import raw credential", value: "import" },
	{ label: "Reinitialize wallet", value: "init" },
	{ label: "Delete wallet initialization", value: "delete-wallet" },
	{ label: "Switch wallet directory", value: "switch" },
	{ label: "Exit", value: "exit" },
] as const;

type InteractiveChoice = (typeof interactiveChoices)[number]["value"];

export async function interactiveWalletAction(rawOptions: unknown) {
	if (!process.stdin.isTTY || !process.stdout.isTTY) {
		throw new Error(
			"Interactive mode requires a TTY. Use an explicit subcommand for non-interactive usage.",
		);
	}

	const options = (rawOptions ?? {}) as { walletDir?: string };
	const prompt = new PromptSession();
	let walletDir = await prompt.text("Wallet directory", {
		defaultValue: options.walletDir ?? "./wallet-data",
	});

	try {
		while (true) {
			const choice = await prompt.choose("Wallet CLI", [...interactiveChoices]);

			stdout.write("\n");

			try {
				const nextWalletDir = await runInteractiveChoice({
					prompt,
					walletDir,
					choice,
				});
				if (nextWalletDir === undefined) {
					return;
				}
				walletDir = nextWalletDir;
			} catch (error) {
				process.stderr.write(`${formatInteractiveError(error)}\n\n`);
			}
		}
	} finally {
		prompt.close();
	}
}

export async function runInteractiveChoice({
	prompt,
	walletDir,
	choice,
}: {
	prompt: PromptSession;
	walletDir: string;
	choice: InteractiveChoice;
}): Promise<string | undefined> {
	switch (choice) {
		case "exit":
			return undefined;
		case "switch": {
			const nextWalletDir = await prompt.text("Wallet directory", {
				defaultValue: walletDir,
			});
			stdout.write(`Using wallet ${nextWalletDir}.\n\n`);
			return nextWalletDir;
		}
		case "init": {
			const alg = await prompt.choose("Holder key algorithm", [
				{ label: "ES256", value: "ES256" },
				{ label: "ES384", value: "ES384" },
				{ label: "EdDSA", value: "EdDSA" },
			]);
			const result = await initWalletAction({ walletDir, alg });
			stdout.write(
				`${formatInitResult({ walletDir, holderKey: result.holderKey, imported: result.imported })}\n\n`,
			);
			return walletDir;
		}
		case "receive": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const offer = await prompt.text("Credential offer or offer URI");
			const result = await receiveCredentialAction({ walletDir, offer });
			stdout.write(
				`${formatCredentialSummary("Received", result.credential)}\n\n`,
			);
			return walletDir;
		}
		case "import": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const credential = await prompt.text("Compact dc+sd-jwt credential");
			const result = await importCredentialAction({
				walletDir,
				credential,
			});
			stdout.write(
				`${formatCredentialSummary("Imported", result.credential)}\n\n`,
			);
			return walletDir;
		}
		case "list": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const result = await listCredentialsAction({ walletDir });
			stdout.write(`${formatCredentialList(result.credentials)}\n\n`);
			return walletDir;
		}
		case "show": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const credentialId = await chooseCredentialId(prompt, walletDir);
			if (credentialId === null) {
				return walletDir;
			}
			const result = await showCredentialAction({
				walletDir,
				credentialId,
			});
			if (result.statusWarning) {
				process.stderr.write(
					`Warning: failed to resolve credential status: ${result.statusWarning}\n`,
				);
			}
			stdout.write(
				`${formatCredentialDetails({
					credential: result.credential,
					status: result.status,
					statusWarning: result.statusWarning,
				})}\n\n`,
			);
			return walletDir;
		}
		case "delete": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const credentialId = await chooseCredentialId(prompt, walletDir);
			if (credentialId === null) {
				return walletDir;
			}
			const confirmed = await prompt.confirm(
				`Delete credential ${credentialId}?`,
				false,
			);
			if (!confirmed) {
				stdout.write("Action cancelled.\n\n");
				return walletDir;
			}
			await deleteCredentialAction({ walletDir, credentialId });
			stdout.write(`${formatDeleteCredentialSummary(credentialId)}\n\n`);
			return walletDir;
		}
		case "delete-all": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const confirmed = await prompt.confirm("Delete all credentials?", false);
			if (!confirmed) {
				stdout.write("Action cancelled.\n\n");
				return walletDir;
			}
			const result = await deleteAllCredentialsAction({ walletDir });
			stdout.write(`${formatDeleteAllCredentialsSummary(result.deleted)}\n\n`);
			return walletDir;
		}
		case "present": {
			if (!(await ensureWalletReady(prompt, walletDir))) {
				return walletDir;
			}
			const request = await prompt.text(
				"OpenID4VP request JSON or openid4vp:// URL",
			);
			const result = await presentCredentialAction({
				walletDir,
				request,
			});
			stdout.write(`${formatPresentationSummary(result)}\n\n`);
			return walletDir;
		}
		case "delete-wallet": {
			if (!(await walletExists(walletDir))) {
				stdout.write(`Wallet ${walletDir} is not initialized yet.\n\n`);
				return walletDir;
			}
			const confirmed = await prompt.confirm(
				`Delete wallet initialization at ${walletDir} and exit?`,
				false,
			);
			if (!confirmed) {
				stdout.write("Action cancelled.\n\n");
				return walletDir;
			}
			await deleteWalletAction({ walletDir });
			stdout.write(`${formatDeleteWalletSummary(walletDir)}\n\n`);
			return undefined;
		}
	}
}

async function ensureWalletReady(prompt: PromptSession, walletDir: string) {
	if (await walletExists(walletDir)) {
		return true;
	}
	stdout.write(`Wallet ${walletDir} is not initialized yet.\n`);
	const createNow = await prompt.confirm("Create it now?", true);
	if (!createNow) {
		stdout.write("Action cancelled.\n\n");
		return false;
	}
	const alg = await prompt.choose("Holder key algorithm", [
		{ label: "ES256", value: "ES256" },
		{ label: "ES384", value: "ES384" },
		{ label: "EdDSA", value: "EdDSA" },
	]);
	const result = await initWalletAction({ walletDir, alg });
	stdout.write(
		`${formatInitResult({ walletDir, holderKey: result.holderKey, imported: result.imported })}\n\n`,
	);
	return true;
}

async function walletExists(walletDir: string) {
	try {
		await access(walletDir);
		await access(`${walletDir}/wallet.json`);
		await access(`${walletDir}/holder-key.json`);
		return true;
	} catch {
		return false;
	}
}

function formatInteractiveError(error: unknown): string {
	if (error instanceof Error && error.message.trim()) {
		return error.message;
	}
	return String(error);
}
