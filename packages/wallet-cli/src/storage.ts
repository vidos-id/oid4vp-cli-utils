import {
	mkdir,
	readdir,
	readFile,
	rm,
	unlink,
	writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
	type HolderKeyRecord,
	HolderKeyRecordSchema,
	type StoredCredentialRecord,
	StoredCredentialRecordSchema,
	type WalletStorage,
} from "@vidos-id/wallet";
import { z } from "zod";

const walletManifestSchema = z.object({
	version: z.literal(1),
	credentials: z
		.array(
			z.object({
				id: z.string().min(1),
				fileName: z.string().min(1),
				issuer: z.string().min(1),
				vct: z.string().min(1),
				importedAt: z.string().datetime(),
			}),
		)
		.default([]),
	updatedAt: z.string().datetime(),
});

type WalletManifest = z.infer<typeof walletManifestSchema>;

const defaultManifest = (): WalletManifest => ({
	version: 1,
	credentials: [],
	updatedAt: new Date().toISOString(),
});

const isMissingFileError = (error: unknown) =>
	error instanceof Error && "code" in error && error.code === "ENOENT";

export class FileSystemWalletStorage implements WalletStorage {
	private readonly walletDir: string;
	private readonly holderKeyPath: string;
	private readonly manifestPath: string;
	private readonly credentialsDir: string;

	constructor(walletDir: string) {
		this.walletDir = walletDir;
		this.holderKeyPath = join(walletDir, "holder-key.json");
		this.manifestPath = join(walletDir, "wallet.json");
		this.credentialsDir = join(walletDir, "credentials");
	}

	async getHolderKey(): Promise<HolderKeyRecord | null> {
		const parsed = await readJsonFile(
			this.holderKeyPath,
			HolderKeyRecordSchema,
		);
		return parsed ?? null;
	}

	async setHolderKey(record: HolderKeyRecord): Promise<void> {
		await this.ensureLayout();
		await writeJsonFile(
			this.holderKeyPath,
			HolderKeyRecordSchema.parse(record),
		);
	}

	async listCredentials(): Promise<StoredCredentialRecord[]> {
		await this.ensureLayout();
		const manifest = (await this.readManifest()) ?? defaultManifest();
		const records = await Promise.all(
			manifest.credentials.map(async ({ id }) => this.getCredential(id)),
		);
		return records.filter(
			(record): record is StoredCredentialRecord => record !== null,
		);
	}

	async getCredential(id: string): Promise<StoredCredentialRecord | null> {
		await this.ensureLayout();
		const filePath = this.credentialPath(id);
		const parsed = await readJsonFile(filePath, StoredCredentialRecordSchema);
		return parsed ?? null;
	}

	async setCredential(record: StoredCredentialRecord): Promise<void> {
		await this.ensureLayout();
		const parsed = StoredCredentialRecordSchema.parse(record);
		await writeJsonFile(this.credentialPath(parsed.id), parsed);

		const manifest = (await this.readManifest()) ?? defaultManifest();
		const entry = {
			id: parsed.id,
			fileName: this.credentialFileName(parsed.id),
			issuer: parsed.issuer,
			vct: parsed.vct,
			importedAt: parsed.importedAt,
		};
		const existingIndex = manifest.credentials.findIndex(
			(candidate) => candidate.id === parsed.id,
		);
		if (existingIndex >= 0) {
			manifest.credentials[existingIndex] = entry;
		} else {
			manifest.credentials.push(entry);
		}
		manifest.updatedAt = new Date().toISOString();
		await writeJsonFile(this.manifestPath, manifest);
	}

	async deleteCredential(id: string): Promise<boolean> {
		await this.ensureLayout();
		const manifest = (await this.readManifest()) ?? defaultManifest();
		const nextCredentials = manifest.credentials.filter(
			(candidate) => candidate.id !== id,
		);
		if (nextCredentials.length === manifest.credentials.length) {
			return false;
		}

		await unlinkIfExists(this.credentialPath(id));
		manifest.credentials = nextCredentials;
		manifest.updatedAt = new Date().toISOString();
		await writeJsonFile(this.manifestPath, manifest);
		return true;
	}

	async deleteAllCredentials(): Promise<number> {
		await this.ensureLayout();
		const manifest = (await this.readManifest()) ?? defaultManifest();
		const deleted = manifest.credentials.length;
		await Promise.all(
			manifest.credentials.map(({ id }) =>
				unlinkIfExists(this.credentialPath(id)),
			),
		);
		manifest.credentials = [];
		manifest.updatedAt = new Date().toISOString();
		await writeJsonFile(this.manifestPath, manifest);
		return deleted;
	}

	async deleteWallet(): Promise<void> {
		await rm(this.walletDir, { recursive: true, force: true });
	}

	private async ensureLayout(): Promise<void> {
		await mkdir(this.credentialsDir, { recursive: true });
		if ((await this.readManifest()) === null) {
			await writeJsonFile(this.manifestPath, defaultManifest());
		}
	}

	private async readManifest(): Promise<WalletManifest | null> {
		const parsed = await readJsonFile(this.manifestPath, walletManifestSchema);
		if (parsed) {
			return parsed;
		}

		const fileNames = await readDirectoryNames(this.credentialsDir);
		if (fileNames.length === 0) {
			return null;
		}

		const credentials = await Promise.all(
			fileNames
				.filter((fileName) => fileName.endsWith(".json"))
				.map(async (fileName) => {
					const record = await readJsonFile(
						join(this.credentialsDir, fileName),
						StoredCredentialRecordSchema,
					);
					return record
						? {
								id: record.id,
								fileName,
								issuer: record.issuer,
								vct: record.vct,
								importedAt: record.importedAt,
							}
						: null;
				}),
		);
		const manifest = {
			version: 1 as const,
			credentials: credentials.filter((record) => record !== null),
			updatedAt: new Date().toISOString(),
		};
		await writeJsonFile(this.manifestPath, manifest);
		return manifest;
	}

	private credentialPath(id: string): string {
		return join(this.credentialsDir, this.credentialFileName(id));
	}

	private credentialFileName(id: string): string {
		return `${encodeURIComponent(id)}.json`;
	}
}

async function readJsonFile<T>(
	filePath: string,
	schema: z.ZodType<T>,
): Promise<T | null> {
	try {
		const content = await readFile(filePath, "utf8");
		return schema.parse(JSON.parse(content) as unknown);
	} catch (error) {
		if (isMissingFileError(error)) {
			return null;
		}
		throw error;
	}
}

async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
	await writeFile(filePath, JSON.stringify(value, null, 2), "utf8");
}

async function unlinkIfExists(filePath: string): Promise<void> {
	try {
		await unlink(filePath);
	} catch (error) {
		if (isMissingFileError(error)) {
			return;
		}
		throw error;
	}
}

async function readDirectoryNames(directoryPath: string): Promise<string[]> {
	try {
		return await readdir(directoryPath);
	} catch (error) {
		if (isMissingFileError(error)) {
			return [];
		}
		throw error;
	}
}
