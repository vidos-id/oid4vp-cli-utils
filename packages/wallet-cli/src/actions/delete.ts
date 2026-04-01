import { deleteOptionsSchema } from "../schemas.ts";
import { FileSystemWalletStorage } from "../storage.ts";

const deleteWalletOptionsSchema = deleteOptionsSchema.omit({
	credentialId: true,
});

export async function deleteCredentialAction(rawOptions: unknown) {
	const options = deleteOptionsSchema.parse(rawOptions);
	const storage = new FileSystemWalletStorage(options.walletDir);
	await storage.deleteCredential(options.credentialId);
	return { credentialId: options.credentialId };
}

export async function deleteAllCredentialsAction(rawOptions: unknown) {
	const options = deleteWalletOptionsSchema.parse(rawOptions);
	const storage = new FileSystemWalletStorage(options.walletDir);
	const deleted = await storage.deleteAllCredentials();
	return { deleted };
}

export async function deleteWalletAction(rawOptions: unknown) {
	const options = deleteWalletOptionsSchema.parse(rawOptions);
	const storage = new FileSystemWalletStorage(options.walletDir);
	await storage.deleteWallet();
	return { walletDir: options.walletDir };
}
