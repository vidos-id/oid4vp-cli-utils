import type { StoredCredentialRecord, WalletStorage } from "wallet";

export class SelectedCredentialStorage implements WalletStorage {
	constructor(
		private readonly base: WalletStorage,
		private readonly selectedCredential: StoredCredentialRecord,
	) {}

	getHolderKey() {
		return this.base.getHolderKey();
	}

	setHolderKey(record: Awaited<ReturnType<WalletStorage["getHolderKey"]>>) {
		if (!record) {
			throw new Error("holder key is required");
		}
		return this.base.setHolderKey(record);
	}

	async listCredentials() {
		return [this.selectedCredential];
	}

	async getCredential(id: string) {
		if (id !== this.selectedCredential.id) {
			return null;
		}
		return this.selectedCredential;
	}

	setCredential(record: StoredCredentialRecord) {
		return this.base.setCredential(record);
	}
}
