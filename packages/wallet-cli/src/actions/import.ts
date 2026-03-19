import { Wallet } from "wallet";
import { readTextInput } from "../io.ts";
import { resolveIssuerKeyMaterial } from "../issuer.ts";
import { importOptionsSchema } from "../schemas.ts";
import { FileSystemWalletStorage } from "../storage.ts";

export async function importCredentialAction(rawOptions: unknown) {
	const options = importOptionsSchema.parse(rawOptions);
	const wallet = new Wallet(new FileSystemWalletStorage(options.walletDir));
	const credential = await readTextInput(
		options.credential,
		options.credentialFile,
	);
	const issuer = await resolveIssuerKeyMaterial(options);
	const imported = await wallet.importCredential({ credential, issuer });
	return { credential: imported };
}
