import { Wallet } from "wallet";
import { listOptionsSchema } from "../schemas.ts";
import { FileSystemWalletStorage } from "../storage.ts";

export async function listCredentialsAction(rawOptions: unknown) {
	const options = listOptionsSchema.parse(rawOptions);
	const wallet = new Wallet(new FileSystemWalletStorage(options.walletDir));
	const credentials = (await wallet.listCredentials()).filter((credential) => {
		if (options.vct && credential.vct !== options.vct) {
			return false;
		}
		if (options.issuer && credential.issuer !== options.issuer) {
			return false;
		}
		return true;
	});
	return { credentials };
}
