import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export async function readTextInput(
	value?: string,
	filePath?: string,
): Promise<string> {
	if (value !== undefined) {
		return value;
	}
	if (filePath !== undefined) {
		return readFile(filePath, "utf8");
	}
	throw new Error("Expected inline value or file path");
}

export async function writeOptionalFile(
	filePath: string | undefined,
	value: unknown,
) {
	if (!filePath) {
		return;
	}
	await mkdir(dirname(filePath), { recursive: true });
	if (typeof value === "string") {
		await writeFile(filePath, value, "utf8");
		return;
	}
	await writeFile(filePath, JSON.stringify(value, null, 2), "utf8");
}

export function printResult(value: unknown, format: string) {
	if (format === "json" || format === "pretty") {
		process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
		return;
	}
	process.stdout.write(`${String(value)}\n`);
}
