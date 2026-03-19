import { describe, expect, test } from "bun:test";
import { resolveCredentialConfigurationId } from "./config.ts";

describe("resolveCredentialConfigurationId", () => {
	test("matches a unique vct", () => {
		const id = resolveCredentialConfigurationId(
			{
				issuer: "https://issuer.example",
				signingKey: {
					alg: "EdDSA",
					privateJwk: { kty: "OKP", crv: "Ed25519", d: "d", x: "x" },
					publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
				},
				credentialConfigurationsSupported: {
					alpha: {
						format: "dc+sd-jwt",
						vct: "vct-a",
						proof_signing_alg_values_supported: ["EdDSA"],
					},
					beta: {
						format: "dc+sd-jwt",
						vct: "vct-b",
						proof_signing_alg_values_supported: ["EdDSA"],
					},
				},
				nonceTtlSeconds: 300,
				grantTtlSeconds: 600,
				tokenTtlSeconds: 600,
			},
			{ vct: "vct-b" },
		);

		expect(id).toBe("beta");
	});

	test("rejects ambiguous resolution", () => {
		expect(() =>
			resolveCredentialConfigurationId(
				{
					issuer: "https://issuer.example",
					signingKey: {
						alg: "EdDSA",
						privateJwk: { kty: "OKP", crv: "Ed25519", d: "d", x: "x" },
						publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
					},
					credentialConfigurationsSupported: {
						alpha: {
							format: "dc+sd-jwt",
							vct: "shared-vct",
							proof_signing_alg_values_supported: ["EdDSA"],
						},
						beta: {
							format: "dc+sd-jwt",
							vct: "shared-vct",
							proof_signing_alg_values_supported: ["EdDSA"],
						},
					},
					nonceTtlSeconds: 300,
					grantTtlSeconds: 600,
					tokenTtlSeconds: 600,
				},
				{ vct: "shared-vct" },
			),
		).toThrow(
			"Provide --credential-configuration-id or a uniquely matching --vct",
		);
	});
});
