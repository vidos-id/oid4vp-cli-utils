import { join } from "node:path";

export function resolveWalletPaths(walletDir: string) {
	return {
		holderKeyFile: join(walletDir, "holder-key.json"),
	};
}

export function resolveIssuerPaths(issuerDir: string) {
	return {
		credentialFile: join(issuerDir, "credential.txt"),
		jwksFile: join(issuerDir, "jwks.json"),
		issuerMetadataFile: join(issuerDir, "issuer-metadata.json"),
	};
}
