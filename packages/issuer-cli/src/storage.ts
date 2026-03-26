import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AccessTokenRecord,
	accessTokenRecordSchema,
	type NonceRecord,
	nonceRecordSchema,
	type PreAuthorizedGrantRecord,
	preAuthorizedGrantRecordSchema,
} from "@vidos-id/issuer";

const STATE_DIR = ".state";

function encodeName(value: string) {
	return encodeURIComponent(value);
}

async function ensureDir(dirPath: string) {
	await mkdir(dirPath, { recursive: true });
}

async function writeJson(filePath: string, value: unknown) {
	await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function readJson(filePath: string) {
	return JSON.parse(await readFile(filePath, "utf8")) as unknown;
}

export class FileSystemIssuerStorage {
	constructor(private readonly issuerDir: string) {}

	private grantsDir() {
		return join(this.issuerDir, STATE_DIR, "grants");
	}

	private accessTokensDir() {
		return join(this.issuerDir, STATE_DIR, "access-tokens");
	}

	private noncesDir() {
		return join(this.issuerDir, STATE_DIR, "nonces");
	}

	async saveGrant(record: PreAuthorizedGrantRecord) {
		await ensureDir(this.grantsDir());
		await writeJson(
			join(this.grantsDir(), `${encodeName(record.preAuthorizedCode)}.json`),
			record,
		);
	}

	async readGrant(preAuthorizedCode: string) {
		return preAuthorizedGrantRecordSchema.parse(
			await readJson(
				join(this.grantsDir(), `${encodeName(preAuthorizedCode)}.json`),
			),
		);
	}

	async saveAccessToken(record: AccessTokenRecord) {
		await ensureDir(this.accessTokensDir());
		await writeJson(
			join(this.accessTokensDir(), `${encodeName(record.accessToken)}.json`),
			record,
		);
	}

	async readAccessToken(accessToken: string) {
		return accessTokenRecordSchema.parse(
			await readJson(
				join(this.accessTokensDir(), `${encodeName(accessToken)}.json`),
			),
		);
	}

	async saveNonce(record: NonceRecord) {
		await ensureDir(this.noncesDir());
		await writeJson(
			join(this.noncesDir(), `${encodeName(record.c_nonce)}.json`),
			record,
		);
	}

	async readNonce(cNonce: string) {
		return nonceRecordSchema.parse(
			await readJson(join(this.noncesDir(), `${encodeName(cNonce)}.json`)),
		);
	}
}
