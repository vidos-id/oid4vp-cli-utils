import { readFile } from "node:fs/promises";

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

export function printResult(value: unknown, format: string) {
	if (format === "json" || format === "pretty") {
		process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
		return;
	}
	process.stdout.write(`${String(value)}\n`);
}
