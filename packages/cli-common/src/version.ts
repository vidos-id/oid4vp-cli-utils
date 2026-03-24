import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export async function readPackageVersion(
	packageJsonPath: string,
): Promise<string> {
	try {
		const content = JSON.parse(
			await readFile(packageJsonPath, "utf8"),
		) as Record<string, unknown>;
		return typeof content.version === "string" ? content.version : "0.0.0";
	} catch {
		return "0.0.0";
	}
}

/**
 * Resolve the package.json path relative to the caller's directory.
 * Pass `import.meta.url` from the entry point.
 */
export function resolvePackageJsonPath(importMetaUrl: string): string {
	const dir = dirname(new URL(importMetaUrl).pathname);
	return join(dir, "..", "package.json");
}
