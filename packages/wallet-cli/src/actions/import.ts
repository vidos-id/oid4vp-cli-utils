import { readFile } from "node:fs/promises";
import { Wallet } from "wallet";
import { importOptionsSchema } from "../schemas.ts";
import { FileSystemWalletStorage } from "../storage.ts";

export async function importCredentialAction(rawOptions: unknown) {
	const options = importOptionsSchema.parse(rawOptions);
	const wallet = new Wallet(new FileSystemWalletStorage(options.walletDir));
	const credentialText =
		options.credential ??
		(await readFile(options.credentialFile as string, "utf8"));
	const credential = credentialText.trim();
	const imported = await wallet.importCredential({ credential });
	return { credential: imported };
}
