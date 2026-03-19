import { describe, expect, test } from "bun:test";
import type { StoredCredentialRecord, WalletStorage } from "wallet";
import { SelectedCredentialStorage } from "./selected-storage.ts";

const selectedCredential: StoredCredentialRecord = {
	id: "cred-1",
	format: "dc+sd-jwt",
	issuer: "https://issuer.example",
	vct: "https://example.com/credential",
	compactSdJwt: "jwt",
	holderKeyId: "holder-1",
	claims: { sub: "123" },
	importedAt: new Date(0).toISOString(),
};

function createBaseStorage(): WalletStorage {
	return {
		getHolderKey: async () => null,
		setHolderKey: async () => undefined,
		listCredentials: async () => [],
		getCredential: async () => null,
		setCredential: async () => undefined,
	};
}

describe("SelectedCredentialStorage", () => {
	test("returns only the selected credential", async () => {
		const storage = new SelectedCredentialStorage(
			createBaseStorage(),
			selectedCredential,
		);

		expect(await storage.listCredentials()).toEqual([selectedCredential]);
		expect(await storage.getCredential("cred-1")).toEqual(selectedCredential);
		expect(await storage.getCredential("cred-2")).toBeNull();
	});

	test("rejects clearing the holder key", async () => {
		const storage = new SelectedCredentialStorage(
			createBaseStorage(),
			selectedCredential,
		);

		expect(() => storage.setHolderKey(null)).toThrow("holder key is required");
	});
});
