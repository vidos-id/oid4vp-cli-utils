import { defineConfig, type UserConfig } from "tsdown";

function createBaseConfig(): UserConfig {
	return defineConfig({
		entry: "src/index.ts",
		format: "esm",
		dts: {
			resolver: "tsc",
		},
		platform: "node",
		target: "node20",
		fixedExtension: true,
		clean: true,
		deps: {
			skipNodeModulesBundle: true,
		},
	});
}

export function createLibraryConfig(): UserConfig {
	return createBaseConfig();
}

export function createCliConfig(): UserConfig {
	return createBaseConfig();
}
