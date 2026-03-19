import {
	type HolderKeyRecord,
	HolderKeyRecordSchema,
	type StoredCredentialRecord,
	StoredCredentialRecordSchema,
} from "./schemas.ts";

export interface WalletStorage {
	getHolderKey(): Promise<HolderKeyRecord | null>;
	setHolderKey(record: HolderKeyRecord): Promise<void>;
	listCredentials(): Promise<StoredCredentialRecord[]>;
	getCredential(id: string): Promise<StoredCredentialRecord | null>;
	setCredential(record: StoredCredentialRecord): Promise<void>;
}

export class InMemoryWalletStorage implements WalletStorage {
	private holderKey: HolderKeyRecord | null = null;
	private readonly credentials = new Map<string, StoredCredentialRecord>();

	async getHolderKey(): Promise<HolderKeyRecord | null> {
		return this.holderKey ? HolderKeyRecordSchema.parse(this.holderKey) : null;
	}

	async setHolderKey(record: HolderKeyRecord): Promise<void> {
		this.holderKey = HolderKeyRecordSchema.parse(record);
	}

	async listCredentials(): Promise<StoredCredentialRecord[]> {
		return [...this.credentials.values()].map((record) =>
			StoredCredentialRecordSchema.parse(record),
		);
	}

	async getCredential(id: string): Promise<StoredCredentialRecord | null> {
		const record = this.credentials.get(id);
		return record ? StoredCredentialRecordSchema.parse(record) : null;
	}

	async setCredential(record: StoredCredentialRecord): Promise<void> {
		const parsed = StoredCredentialRecordSchema.parse(record);
		this.credentials.set(parsed.id, parsed);
	}
}
