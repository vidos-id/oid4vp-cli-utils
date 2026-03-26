import { SDJwt } from "@sd-jwt/core";
import { hasher } from "@sd-jwt/hash";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { JWK, JWTVerifyResult } from "jose";
import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import { z } from "zod";
import { IssuerError } from "./errors.ts";
import {
	type AccessTokenRecord,
	type ClaimSet,
	type CreateCredentialOfferInput,
	type CreatePreAuthorizedGrantInput,
	createCredentialOfferInputSchema,
	createPreAuthorizedGrantInputSchema,
	type ExchangePreAuthorizedCodeInput,
	exchangePreAuthorizedCodeInputSchema,
	type IssueCredentialInput,
	type IssuerConfig,
	type IssuerConfigInput,
	issueCredentialInputSchema,
	issuerConfigSchema,
	jwkSchema,
	type NonceRecord,
	type PreAuthorizedGrantRecord,
	type ValidateProofJwtInput,
	validateProofJwtInputSchema,
} from "./schemas.ts";
import {
	cloneJson,
	fromBase64Url,
	nowInSeconds,
	randomToken,
	toBase64Url,
} from "./utils.ts";

export type IssuerMetadata = ReturnType<DemoIssuer["getMetadata"]>;

export type ValidatedProof = {
	nonce: string;
	holderPublicJwk: JWK;
	holderKeyThumbprint: string;
	payload: Record<string, unknown>;
	protectedHeader: Record<string, unknown>;
	updatedNonce: NonceRecord;
};

type IssuanceBinding = {
	holderPublicJwk?: JWK;
	holderKeyThumbprint?: string;
};

const RESERVED_CREDENTIAL_CLAIMS = new Set([
	"iss",
	"nbf",
	"exp",
	"cnf",
	"vct",
	"status",
	"iat",
]);

const deriveDisclosureFrame = (claims: ClaimSet) => {
	const topLevelClaims = Object.keys(claims).filter(
		(claim) => !RESERVED_CREDENTIAL_CLAIMS.has(claim),
	);
	if (topLevelClaims.length === 0) {
		return undefined;
	}
	return { _sd: topLevelClaims };
};

const sanitizeCredentialClaims = (claims: ClaimSet): ClaimSet =>
	Object.fromEntries(
		Object.entries(claims).filter(
			([claim]) => !RESERVED_CREDENTIAL_CLAIMS.has(claim),
		),
	);

const subtleAlgorithm = (alg: string): AlgorithmIdentifier | EcdsaParams => {
	if (alg === "EdDSA") {
		return "Ed25519";
	}
	if (alg === "ES384") {
		return { name: "ECDSA", hash: "SHA-384" };
	}
	return { name: "ECDSA", hash: "SHA-256" };
};

const createSdJwtSigner =
	(privateKey: CryptoKey, alg: string) => async (input: string) => {
		const signature = await crypto.subtle.sign(
			subtleAlgorithm(alg),
			privateKey,
			new TextEncoder().encode(input),
		);
		return toBase64Url(new Uint8Array(signature));
	};

const createSdJwtVerifier =
	(publicKey: CryptoKey, alg: string) =>
	async (input: string, signature: string) => {
		return crypto.subtle.verify(
			subtleAlgorithm(alg),
			publicKey,
			fromBase64Url(signature),
			new TextEncoder().encode(input),
		);
	};

const holderJwkSchema = jwkSchema.refine(
	(value) => Boolean(value.kty && (value.x || value.n)),
	"Holder proof must contain an embedded public JWK",
);

const proofPayloadSchema = z.object({
	aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
	nonce: z.string().min(1),
	cnf: z.object({ jwk: holderJwkSchema }).optional(),
});

export class DemoIssuer {
	private readonly config: IssuerConfig;
	private readonly now: () => number;
	private readonly idGenerator: () => string;
	private readonly issuerPrivateKeyPromise: Promise<CryptoKey>;
	private readonly issuerPublicKeyPromise: Promise<CryptoKey>;
	private readonly sdJwtVc: Promise<SDJwtVcInstance>;

	constructor(
		config: IssuerConfigInput,
		options?: { now?: () => number; idGenerator?: () => string },
	) {
		this.config = issuerConfigSchema.parse(config);
		this.now = options?.now ?? nowInSeconds;
		this.idGenerator = options?.idGenerator ?? randomToken;
		this.issuerPrivateKeyPromise = importJWK(
			this.config.signingKey.privateJwk,
			this.config.signingKey.alg,
			{
				extractable: false,
			},
		) as Promise<CryptoKey>;
		this.issuerPublicKeyPromise = importJWK(
			this.config.signingKey.publicJwk,
			this.config.signingKey.alg,
			{
				extractable: true,
			},
		) as Promise<CryptoKey>;
		this.sdJwtVc = Promise.all([
			this.issuerPrivateKeyPromise,
			this.issuerPublicKeyPromise,
		]).then(
			([privateKey, publicKey]) =>
				new SDJwtVcInstance({
					signer: createSdJwtSigner(privateKey, this.config.signingKey.alg),
					signAlg: this.config.signingKey.alg,
					verifier: createSdJwtVerifier(publicKey, this.config.signingKey.alg),
					hasher,
					hashAlg: "sha-256",
					saltGenerator: async (length = 16) =>
						toBase64Url(crypto.getRandomValues(new Uint8Array(length))),
				}),
		);
	}

	getJwks() {
		return {
			keys: [cloneJson(this.config.signingKey.publicJwk)],
		};
	}

	getMetadata() {
		const tokenEndpoint =
			this.config.endpoints?.token ??
			new URL("/token", this.config.issuer).toString();
		const credentialEndpoint =
			this.config.endpoints?.credential ??
			new URL("/credential", this.config.issuer).toString();
		const nonceEndpoint =
			this.config.endpoints?.nonce ??
			new URL("/nonce", this.config.issuer).toString();

		return {
			credential_issuer: this.config.issuer,
			token_endpoint: tokenEndpoint,
			credential_endpoint: credentialEndpoint,
			nonce_endpoint: nonceEndpoint,
			jwks: this.getJwks(),
			credential_configurations_supported: Object.fromEntries(
				Object.entries(this.config.credentialConfigurationsSupported).map(
					([id, entry]) => [
						id,
						{
							format: entry.format,
							vct: entry.vct,
							scope: entry.scope,
							proof_types_supported: {
								jwt: {
									proof_signing_alg_values_supported:
										entry.proof_signing_alg_values_supported,
								},
							},
							cryptographic_binding_methods_supported: ["jwk"],
							credential_signing_alg_values_supported: [
								this.config.signingKey.alg,
							],
						},
					],
				),
			),
		};
	}

	createPreAuthorizedGrant(input: CreatePreAuthorizedGrantInput) {
		const parsed = createPreAuthorizedGrantInputSchema.parse(input);
		const configuration =
			this.config.credentialConfigurationsSupported[
				parsed.credential_configuration_id
			];
		if (!configuration) {
			throw new IssuerError(
				"unsupported_credential_configuration",
				"Unsupported credential_configuration_id",
			);
		}
		const preAuthorizedCode = this.idGenerator();
		const issuedAt = this.now();
		const expiresAt =
			issuedAt + (parsed.expires_in ?? this.config.grantTtlSeconds);
		const preAuthorizedGrant = {
			preAuthorizedCode,
			credentialConfigurationId: parsed.credential_configuration_id,
			claims: cloneJson(parsed.claims),
			expiresAt,
			used: false,
		} satisfies PreAuthorizedGrantRecord;

		return {
			preAuthorizedCode,
			expiresAt,
			credential_configuration_id: parsed.credential_configuration_id,
			preAuthorizedGrant,
		};
	}

	createCredentialOffer(input: CreateCredentialOfferInput) {
		const parsed = createCredentialOfferInputSchema.parse(input);
		const grant = this.createPreAuthorizedGrant(parsed);
		return {
			credential_issuer: this.config.issuer,
			credential_configuration_ids: [grant.credential_configuration_id],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": grant.preAuthorizedCode,
				},
			},
			preAuthorizedGrant: grant.preAuthorizedGrant,
		};
	}

	exchangePreAuthorizedCode(input: ExchangePreAuthorizedCodeInput) {
		const parsed = exchangePreAuthorizedCodeInputSchema.parse(input);
		if (parsed.tokenRequest.tx_code) {
			throw new IssuerError(
				"unsupported_tx_code",
				"tx_code is not supported in this demo issuer",
			);
		}
		if (
			parsed.preAuthorizedGrant.preAuthorizedCode !==
			parsed.tokenRequest["pre-authorized_code"]
		) {
			throw new IssuerError(
				"invalid_grant",
				"Invalid or expired pre-authorized code",
			);
		}
		if (
			parsed.preAuthorizedGrant.used ||
			parsed.preAuthorizedGrant.expiresAt <= this.now()
		) {
			throw new IssuerError(
				"invalid_grant",
				"Invalid or expired pre-authorized code",
			);
		}
		const accessToken = this.idGenerator();
		const expiresIn = this.config.tokenTtlSeconds;
		const updatedPreAuthorizedGrant = {
			...parsed.preAuthorizedGrant,
			used: true,
		} satisfies PreAuthorizedGrantRecord;
		const accessTokenRecord = {
			accessToken,
			credentialConfigurationId:
				parsed.preAuthorizedGrant.credentialConfigurationId,
			claims: cloneJson(parsed.preAuthorizedGrant.claims),
			expiresAt: this.now() + expiresIn,
			used: false,
		} satisfies AccessTokenRecord;

		return {
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: expiresIn,
			credential_configuration_id:
				parsed.preAuthorizedGrant.credentialConfigurationId,
			accessTokenRecord,
			updatedPreAuthorizedGrant,
		};
	}

	createNonce() {
		const c_nonce = this.idGenerator();
		const expiresIn = this.config.nonceTtlSeconds;
		const nonce = {
			c_nonce,
			expiresAt: this.now() + expiresIn,
			used: false,
		} satisfies NonceRecord;
		return {
			c_nonce,
			c_nonce_expires_in: expiresIn,
			nonce,
		};
	}

	async validateProofJwt(input: ValidateProofJwtInput) {
		const parsed = validateProofJwtInputSchema.parse(input);
		const protectedHeader = decodeProtectedHeader(parsed.jwt) as Record<
			string,
			unknown
		>;
		if (protectedHeader.typ !== "openid4vci-proof+jwt") {
			throw new IssuerError(
				"invalid_proof",
				"Proof JWT typ must be openid4vci-proof+jwt",
			);
		}
		if (
			typeof protectedHeader.alg !== "string" ||
			protectedHeader.alg.length === 0
		) {
			throw new IssuerError("invalid_proof", "Proof JWT alg is required");
		}
		const embeddedJwk = holderJwkSchema.safeParse(protectedHeader.jwk);
		if (!embeddedJwk.success) {
			throw new IssuerError(
				"invalid_proof",
				"Proof JWT must contain an embedded public JWK in the protected header",
			);
		}
		const importedFromHeader = await importJWK(
			embeddedJwk.data,
			protectedHeader.alg,
			{
				extractable: true,
			},
		);
		let verified: JWTVerifyResult<Record<string, unknown>>;
		try {
			verified = await jwtVerify(parsed.jwt, importedFromHeader, {
				audience: this.config.issuer,
			});
		} catch (error) {
			throw new IssuerError(
				"invalid_proof",
				error instanceof Error
					? error.message
					: "Proof JWT verification failed",
			);
		}
		const payload = proofPayloadSchema.parse(verified.payload);
		if (parsed.nonce.c_nonce !== payload.nonce) {
			throw new IssuerError(
				"invalid_proof",
				"Proof JWT nonce is invalid or expired",
			);
		}
		if (parsed.nonce.used || parsed.nonce.expiresAt <= this.now()) {
			throw new IssuerError(
				"invalid_proof",
				"Proof JWT nonce is invalid or expired",
			);
		}
		const holderPublicJwk = embeddedJwk.data;
		const updatedNonce = {
			...parsed.nonce,
			used: true,
		} satisfies NonceRecord;

		return {
			nonce: payload.nonce,
			holderPublicJwk: holderPublicJwk as JWK,
			holderKeyThumbprint: await calculateJwkThumbprint(holderPublicJwk as JWK),
			payload: cloneJson(verified?.payload as Record<string, unknown>),
			protectedHeader: cloneJson(protectedHeader),
			updatedNonce,
		} satisfies ValidatedProof;
	}

	async issueCredential(
		input: IssueCredentialInput & { proof?: ValidatedProof },
	) {
		const parsed = issueCredentialInputSchema.parse(input);
		if (parsed.accessToken.used || parsed.accessToken.expiresAt <= this.now()) {
			throw new IssuerError("invalid_token", "Invalid or expired access token");
		}
		if (
			parsed.accessToken.credentialConfigurationId !==
			parsed.credential_configuration_id
		) {
			throw new IssuerError(
				"invalid_request",
				"Access token is not valid for credential_configuration_id",
			);
		}
		const configuration =
			this.config.credentialConfigurationsSupported[
				parsed.credential_configuration_id
			];
		if (!configuration) {
			throw new IssuerError(
				"unsupported_credential_configuration",
				"Unsupported credential_configuration_id",
			);
		}
		const binding: IssuanceBinding = input.proof
			? {
					holderPublicJwk: input.proof.holderPublicJwk,
					holderKeyThumbprint: input.proof.holderKeyThumbprint,
				}
			: parsed.holderPublicJwk
				? {
						holderPublicJwk: parsed.holderPublicJwk as JWK,
						holderKeyThumbprint: await calculateJwkThumbprint(
							parsed.holderPublicJwk as JWK,
						),
					}
				: {};
		const sdJwtVc = await this.sdJwtVc;
		const issuedAt = this.now();
		const credentialClaims = sanitizeCredentialClaims(
			parsed.accessToken.claims,
		);
		const payload = {
			iss: this.config.issuer,
			iat: issuedAt,
			vct: configuration.vct,
			cnf: binding.holderPublicJwk
				? {
						jwk: binding.holderPublicJwk,
					}
				: undefined,
			...cloneJson(credentialClaims),
		};
		const credential = await sdJwtVc.issue(
			payload,
			deriveDisclosureFrame(credentialClaims) as never,
			{
				header: {
					kid: this.config.signingKey.publicJwk.kid,
					x5c: this.config.signingKey.publicJwk.x5c,
				},
			},
		);
		const nonce = this.createNonce();
		const updatedAccessToken = {
			...parsed.accessToken,
			used: true,
		} satisfies AccessTokenRecord;
		return {
			format: "dc+sd-jwt" as const,
			credential,
			c_nonce: nonce.c_nonce,
			nonce: nonce.nonce,
			updatedAccessToken,
		};
	}

	async parseIssuedCredential(encoded: string) {
		const sdJwt = await SDJwt.fromEncode(encoded, hasher);
		const jwt = await SDJwt.extractJwt<
			Record<string, unknown>,
			Record<string, unknown>
		>(encoded);
		return {
			jwt: jwt.encodeJwt(),
			header: jwt.header,
			payload: jwt.payload,
			claims: await sdJwt.getClaims<Record<string, unknown>>(hasher),
		};
	}
}

export const createIssuer = (
	config: IssuerConfigInput,
	options?: { now?: () => number; idGenerator?: () => string },
) => new DemoIssuer(config, options);
