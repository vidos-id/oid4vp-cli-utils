import { join } from "node:path";

export function resolveIssuerDirPaths(issuerDir: string) {
	return {
		signingKeyFile: join(issuerDir, "signing-key.json"),
		jwksFile: join(issuerDir, "jwks.json"),
		trustFile: join(issuerDir, "trust.json"),
		credentialFile: join(issuerDir, "credential.txt"),
	};
}
