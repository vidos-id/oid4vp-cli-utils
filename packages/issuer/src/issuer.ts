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
	type ClaimSet,
	type CreateCredentialOfferInput,
	type CreatePreAuthorizedGrantInput,
	type CredentialRequest,
	createCredentialOfferInputSchema,
	createPreAuthorizedGrantInputSchema,
	credentialRequestSchema,
	type IssuerConfig,
	type IssuerConfigInput,
	issuerConfigSchema,
	jwkSchema,
	nonceValidationSchema,
	type TokenRequest,
	tokenRequestSchema,
} from "./schemas.ts";
import {
	cloneJson,
	fromBase64Url,
	nowInSeconds,
	randomToken,
	toBase64Url,
} from "./utils.ts";

type GrantRecord = {
	credentialConfigurationId: string;
	claims: ClaimSet;
	expiresAt: number;
	used: boolean;
};

type AccessTokenRecord = {
	credentialConfigurationId: string;
	claims: ClaimSet;
	expiresAt: number;
	used: boolean;
};

type NonceRecord = {
	expiresAt: number;
	used: boolean;
};

export type IssuerMetadata = ReturnType<DemoIssuer["getMetadata"]>;

export type ValidatedProof = {
	nonce: string;
	holderPublicJwk: JWK;
	holderKeyThumbprint: string;
	payload: Record<string, unknown>;
	protectedHeader: Record<string, unknown>;
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
	private readonly grants = new Map<string, GrantRecord>();
	private readonly accessTokens = new Map<string, AccessTokenRecord>();
	private readonly nonces = new Map<string, NonceRecord>();
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
		this.grants.set(preAuthorizedCode, {
			credentialConfigurationId: parsed.credential_configuration_id,
			claims: cloneJson(parsed.claims),
			expiresAt,
			used: false,
		});

		return {
			preAuthorizedCode,
			expiresAt,
			credential_configuration_id: parsed.credential_configuration_id,
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
		};
	}

	exchangePreAuthorizedCode(input: TokenRequest) {
		const parsed = tokenRequestSchema.parse(input);
		if (parsed.tx_code) {
			throw new IssuerError(
				"unsupported_tx_code",
				"tx_code is not supported in this demo issuer",
			);
		}
		const record = this.grants.get(parsed["pre-authorized_code"]);
		if (!record || record.used || record.expiresAt <= this.now()) {
			throw new IssuerError(
				"invalid_grant",
				"Invalid or expired pre-authorized code",
			);
		}
		record.used = true;
		const accessToken = this.idGenerator();
		const expiresIn = this.config.tokenTtlSeconds;
		this.accessTokens.set(accessToken, {
			credentialConfigurationId: record.credentialConfigurationId,
			claims: cloneJson(record.claims),
			expiresAt: this.now() + expiresIn,
			used: false,
		});

		return {
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: expiresIn,
			credential_configuration_id: record.credentialConfigurationId,
		};
	}

	createNonce() {
		const nonce = this.idGenerator();
		const expiresIn = this.config.nonceTtlSeconds;
		this.nonces.set(nonce, { expiresAt: this.now() + expiresIn, used: false });
		return {
			c_nonce: nonce,
			c_nonce_expires_in: expiresIn,
		};
	}

	async validateProofJwt(input: { jwt: string }) {
		const parsed = nonceValidationSchema.parse(input);
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
		const holderPublicJwk = embeddedJwk.data;
		const nonceRecord = this.nonces.get(payload.nonce);
		if (
			!nonceRecord ||
			nonceRecord.used ||
			nonceRecord.expiresAt <= this.now()
		) {
			throw new IssuerError(
				"invalid_proof",
				"Proof JWT nonce is invalid or expired",
			);
		}
		nonceRecord.used = true;

		return {
			nonce: payload.nonce,
			holderPublicJwk: holderPublicJwk as JWK,
			holderKeyThumbprint: await calculateJwkThumbprint(holderPublicJwk as JWK),
			payload: cloneJson(verified?.payload as Record<string, unknown>),
			protectedHeader: cloneJson(protectedHeader),
		} satisfies ValidatedProof;
	}

	async issueCredential(input: CredentialRequest) {
		const parsed = credentialRequestSchema.parse(input);
		const accessToken = this.accessTokens.get(parsed.access_token);
		if (
			!accessToken ||
			accessToken.used ||
			accessToken.expiresAt <= this.now()
		) {
			throw new IssuerError("invalid_token", "Invalid or expired access token");
		}
		if (
			accessToken.credentialConfigurationId !==
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
		const binding: IssuanceBinding = parsed.proof
			? await this.validateProofJwt({
					jwt: parsed.proof.jwt,
				})
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
		const credentialClaims = sanitizeCredentialClaims(accessToken.claims);
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
		accessToken.used = true;
		return {
			format: "dc+sd-jwt" as const,
			credential,
			c_nonce: this.createNonce().c_nonce,
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
