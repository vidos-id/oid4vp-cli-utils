import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const workspaceRoot = import.meta.dir
	? join(import.meta.dir, "..")
	: process.cwd();

const publishablePackages = [
	"packages/cli-common/package.json",
	"packages/wallet/package.json",
	"packages/issuer/package.json",
	"packages/issuer-web-shared/package.json",
	"packages/wallet-cli/package.json",
	"packages/issuer-cli/package.json",
] as const;

const internalDependencyNames = new Set([
	"@vidos-id/openid4vc-cli-common",
	"@vidos-id/openid4vc-wallet",
	"@vidos-id/openid4vc-issuer",
	"@vidos-id/openid4vc-issuer-web-shared",
	"@vidos-id/openid4vc-wallet-cli",
	"@vidos-id/openid4vc-issuer-cli",
]);

type PackageJson = {
	name?: string;
	version?: string;
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
	peerDependencies?: Record<string, string>;
	optionalDependencies?: Record<string, string>;
};

function assertVersion(version: string | undefined): string {
	if (!version || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z-.]+)?$/.test(version)) {
		throw new Error("Expected a semver version like 0.10.0");
	}

	return version;
}

function updateDependencyMap(
	dependencies: Record<string, string> | undefined,
	versionByName: Map<string, string>,
) {
	if (!dependencies) {
		return;
	}

	for (const [name, currentVersion] of Object.entries(dependencies)) {
		if (!internalDependencyNames.has(name)) {
			continue;
		}

		const nextVersion = versionByName.get(name);
		if (!nextVersion) {
			throw new Error(
				`Missing release version for internal dependency ${name}`,
			);
		}

		if (currentVersion !== nextVersion) {
			dependencies[name] = nextVersion;
		}
	}
}

async function readPackageJson(relativePath: string): Promise<PackageJson> {
	const absolutePath = join(workspaceRoot, relativePath);
	return JSON.parse(await readFile(absolutePath, "utf8")) as PackageJson;
}

async function writePackageJson(
	relativePath: string,
	packageJson: PackageJson,
) {
	const absolutePath = join(workspaceRoot, relativePath);
	await writeFile(
		absolutePath,
		`${JSON.stringify(packageJson, null, "\t")}\n`,
		"utf8",
	);
}

const nextVersion = assertVersion(process.argv[2]);
const rootPackage = await readPackageJson("package.json");
rootPackage.version = nextVersion;
await writePackageJson("package.json", rootPackage);

const versionByName = new Map<string, string>();

for (const packagePath of publishablePackages) {
	const packageJson = await readPackageJson(packagePath);
	if (!packageJson.name) {
		throw new Error(`Missing package name in ${packagePath}`);
	}
	packageJson.version = nextVersion;
	versionByName.set(packageJson.name, nextVersion);
	await writePackageJson(packagePath, packageJson);
}

for (const packagePath of publishablePackages) {
	const packageJson = await readPackageJson(packagePath);
	updateDependencyMap(packageJson.dependencies, versionByName);
	updateDependencyMap(packageJson.devDependencies, versionByName);
	updateDependencyMap(packageJson.peerDependencies, versionByName);
	updateDependencyMap(packageJson.optionalDependencies, versionByName);
	await writePackageJson(packagePath, packageJson);
}

process.stdout.write(`Updated release version to ${nextVersion}\n`);
