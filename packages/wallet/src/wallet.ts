import { decodeSdJwt, getClaims, splitSdJwt } from "@sd-jwt/decode";
import { present } from "@sd-jwt/present";
import { DcqlPresentation, DcqlQuery, runDcqlQuery } from "dcql";
import type { JWK } from "jose";
import { decodeProtectedHeader, jwtVerify } from "jose";

import {
	createHolderKeyRecord,
	createKbJwt,
	getJwkThumbprint,
	HOLDER_KEY_ALG,
	importPublicKey,
	sdJwtHasher,
	sha256Base64Url,
} from "./crypto.ts";
import {
	type HolderKeyRecord,
	HolderKeyRecordSchema,
	type ImportCredentialInput,
	ImportCredentialInputSchema,
	type IssuerKeyMaterial,
	type OpenId4VpRequestInput,
	OpenId4VpRequestSchema,
	type ParsedDcqlQuery,
	type StoredCredentialRecord,
	StoredCredentialRecordSchema,
} from "./schemas.ts";
import type { WalletStorage } from "./storage.ts";

const RESERVED_TOP_LEVEL_CLAIMS = new Set([
	"_sd",
	"_sd_alg",
	"cnf",
	"exp",
	"iat",
	"iss",
	"jti",
	"nbf",
	"status",
	"sub",
	"vct",
]);

export class WalletError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "WalletError";
	}
}

export type MatchedCredential = {
	queryId: string;
	credentialId: string;
	issuer: string;
	vct: string;
	claims: Record<string, unknown>;
	claimPaths: Array<Array<string | number | null>>;
};

export type QueryCredentialMatches = {
	queryId: string;
	credentials: MatchedCredential[];
};

export type MatchDcqlQueryResult = {
	query: ParsedDcqlQuery;
	credentials: MatchedCredential[];
};

export type InspectDcqlQueryResult = {
	query: ParsedDcqlQuery;
	queries: QueryCredentialMatches[];
};

export type CreatePresentationResult = {
	query: ParsedDcqlQuery;
	vpToken: string;
	dcqlPresentation: Record<string, string[]>;
	matchedCredentials: MatchedCredential[];
};

export class Wallet {
	constructor(private readonly storage: WalletStorage) {}

	async getOrCreateHolderKey(
		alg?: HolderKeyRecord["algorithm"],
	): Promise<HolderKeyRecord> {
		const existing = await this.storage.getHolderKey();
		if (existing) {
			return existing;
		}

		const created = await createHolderKeyRecord(alg);
		await this.storage.setHolderKey(created);
		return created;
	}

	async importHolderKey(input: {
		privateJwk: Record<string, unknown>;
		publicJwk: Record<string, unknown>;
		algorithm: string;
	}): Promise<HolderKeyRecord> {
		const existing = await this.storage.getHolderKey();
		if (existing) {
			throw new WalletError("Holder key already exists in this wallet");
		}
		const id = await getJwkThumbprint(input.publicJwk as JWK);
		const record: HolderKeyRecord = {
			id,
			algorithm: input.algorithm as HolderKeyRecord["algorithm"],
			publicJwk: input.publicJwk,
			privateJwk: input.privateJwk,
			createdAt: new Date().toISOString(),
		};
		HolderKeyRecordSchema.parse(record);
		await this.storage.setHolderKey(record);
		return record;
	}

	async listCredentials(): Promise<StoredCredentialRecord[]> {
		return this.storage.listCredentials();
	}

	getVpFormatsSupported(): {
		"dc+sd-jwt": { kb_jwt_alg_values: string[]; sd_jwt_alg_values: string[] };
	} {
		return {
			"dc+sd-jwt": {
				sd_jwt_alg_values: ["ES256", "ES384", "EdDSA"],
				kb_jwt_alg_values: ["ES256", "ES384", "EdDSA"],
			},
		};
	}

	async importCredential(
		input: ImportCredentialInput,
	): Promise<StoredCredentialRecord> {
		const parsedInput = ImportCredentialInputSchema.parse(input);
		const holderKey = await this.getOrCreateHolderKey();
		const compactSdJwt = normalizeSdJwt(parsedInput.credential);

		const split = splitSdJwt(compactSdJwt);
		if (split.kbJwt) {
			throw new WalletError(
				"Wallet only imports issuer-bound credentials, not presented credentials",
			);
		}

		const header = decodeProtectedHeader(split.jwt);
		if (header.typ !== "dc+sd-jwt") {
			throw new WalletError("Unsupported credential typ");
		}

		let payload: Record<string, unknown>;
		if (parsedInput.issuer) {
			const verificationKey = await resolveIssuerVerificationKey(
				parsedInput.issuer,
				header.kid,
				header.alg,
			);
			const verified = await jwtVerify(split.jwt, verificationKey, {
				issuer: parsedInput.issuer.issuer,
				typ: "dc+sd-jwt",
			});
			payload = verified.payload as Record<string, unknown>;
		} else {
			const jwtPart = split.jwt.split(".")[1];
			if (!jwtPart) {
				throw new WalletError("Invalid credential format");
			}
			const decodedPayload = JSON.parse(
				Buffer.from(jwtPart, "base64url").toString("utf8"),
			) as { iss?: unknown };
			if (
				typeof decodedPayload.iss !== "string" ||
				decodedPayload.iss.length === 0
			) {
				throw new WalletError("Credential is missing issuer");
			}
			payload = decodedPayload;
		}

		const vct = readStringClaim(payload.vct, "Credential is missing vct");
		const issuer = readStringClaim(payload.iss, "Credential is missing iss");
		const cnf = readRecordClaim(payload.cnf, "Credential is missing cnf");
		const cnfJwk = readRecordClaim(
			cnf.jwk,
			"Credential cnf is missing jwk",
		) as JWK;
		const holderThumbprint = await getJwkThumbprint(holderKey.publicJwk as JWK);
		const credentialThumbprint = await getJwkThumbprint(cnfJwk);

		if (holderThumbprint !== credentialThumbprint) {
			throw new WalletError(
				"Credential cnf.jwk does not match the wallet holder key",
			);
		}

		if (typeof payload._sd_alg !== "string") {
			throw new WalletError("Credential is missing _sd_alg");
		}

		const decoded = await decodeSdJwt(compactSdJwt, sdJwtHasher);
		const allClaims = (await getClaims<Record<string, unknown>>(
			decoded.jwt.payload,
			decoded.disclosures,
			sdJwtHasher,
		)) as Record<string, unknown>;

		const credentialRecord = StoredCredentialRecordSchema.parse({
			id:
				typeof payload.jti === "string" && payload.jti.length > 0
					? payload.jti
					: await sha256Base64Url(compactSdJwt),
			format: "dc+sd-jwt",
			compactSdJwt,
			issuer,
			vct,
			holderKeyId: holderKey.id,
			claims: stripReservedClaims(allClaims),
			importedAt: new Date().toISOString(),
		});

		await this.storage.setCredential(credentialRecord);
		return credentialRecord;
	}

	async matchDcqlQuery(
		input: OpenId4VpRequestInput,
	): Promise<MatchDcqlQueryResult> {
		const inspected = await this.inspectDcqlQuery(input);
		return {
			query: inspected.query,
			credentials: inspected.queries.map((queryMatch) => {
				const selected = queryMatch.credentials[0];
				if (!selected) {
					throw new WalletError(
						`No credential matched query ${queryMatch.queryId}`,
					);
				}
				return selected;
			}),
		};
	}

	async inspectDcqlQuery(
		input: OpenId4VpRequestInput,
	): Promise<InspectDcqlQueryResult> {
		const request = OpenId4VpRequestSchema.parse(input);
		const query = DcqlQuery.parse(
			request.dcql_query as never,
		) as ParsedDcqlQuery;
		assertSupportedDcqlQuery(query);

		const credentials = await this.storage.listCredentials();
		const result = runDcqlQuery(query as never, {
			credentials: credentials.map((credential) => ({
				credential_format: "dc+sd-jwt" as const,
				vct: credential.vct,
				claims: credential.claims as never,
				cryptographic_holder_binding: true,
			})) as never,
			presentation: false,
		});

		if (!result.can_be_satisfied) {
			throw new WalletError(
				"No stored credential satisfies the supported DCQL query",
			);
		}

		const queryMatches: QueryCredentialMatches[] = [];
		for (const credentialQuery of query.credentials as Array<
			Record<string, unknown>
		>) {
			const queryId = credentialQuery.id as string;
			const credentialMatch = result.credential_matches[queryId];
			if (
				!credentialMatch?.success ||
				credentialMatch.valid_credentials.length === 0
			) {
				throw new WalletError(`No credential matched query ${queryId}`);
			}

			const claimPaths = (
				(credentialQuery.claims ?? []) as Array<{
					path: Array<string | number | null>;
				}>
			).map((claim) => [...claim.path]);

			queryMatches.push({
				queryId,
				credentials: credentialMatch.valid_credentials.map((candidate) => {
					const storedCredential =
						credentials[candidate.input_credential_index];
					if (!storedCredential) {
						throw new WalletError(
							`Matched credential for query ${queryId} was not found`,
						);
					}

					return {
						queryId,
						credentialId: storedCredential.id,
						issuer: storedCredential.issuer,
						vct: storedCredential.vct,
						claims: storedCredential.claims,
						claimPaths,
					};
				}),
			});
		}

		return { query, queries: queryMatches };
	}

	async createPresentation(
		input: OpenId4VpRequestInput,
		options?: {
			selectedCredentials?: Record<string, string>;
		},
	): Promise<CreatePresentationResult> {
		const request = OpenId4VpRequestSchema.parse(input);
		const holderKey = await this.getOrCreateHolderKey();
		const inspected = await this.inspectDcqlQuery(request);
		const matchedCredentials = inspected.queries.map((queryMatch) => {
			const selectedCredentialId =
				options?.selectedCredentials?.[queryMatch.queryId];
			if (selectedCredentialId) {
				const selected = queryMatch.credentials.find(
					(candidate) => candidate.credentialId === selectedCredentialId,
				);
				if (!selected) {
					throw new WalletError(
						`Credential ${selectedCredentialId} does not satisfy query ${queryMatch.queryId}`,
					);
				}
				return selected;
			}

			const first = queryMatch.credentials[0];
			if (!first) {
				throw new WalletError(
					`No credential matched query ${queryMatch.queryId}`,
				);
			}
			return first;
		});
		const presentations: Record<string, string[]> = {};

		for (const matched of matchedCredentials) {
			const storedCredential = await this.storage.getCredential(
				matched.credentialId,
			);
			if (!storedCredential) {
				throw new WalletError(
					`Stored credential ${matched.credentialId} not found`,
				);
			}

			const frame =
				matched.claimPaths.length === 0
					? undefined
					: claimPathsToPresentationFrame(matched.claimPaths);
			const normalized = normalizeSdJwt(storedCredential.compactSdJwt);
			const sdJwtPresentation = await present(
				normalized,
				(frame ?? {}) as never,
				sdJwtHasher,
			);
			const kbJwt = await createKbJwt({
				holderPrivateJwk: holderKey.privateJwk as JWK,
				aud: request.client_id,
				nonce: request.nonce,
				sdJwtPresentation,
			});

			presentations[matched.queryId] = [
				`${stripTrailingEmptyPart(sdJwtPresentation)}~${kbJwt}`,
			];
		}

		return {
			query: inspected.query,
			matchedCredentials,
			dcqlPresentation: presentations,
			vpToken: DcqlPresentation.encode(presentations as never),
		};
	}
}

function normalizeSdJwt(compact: string): string {
	return compact.endsWith("~") ? compact : `${compact}~`;
}

function stripTrailingEmptyPart(compact: string): string {
	return compact.endsWith("~") ? compact.slice(0, -1) : compact;
}

async function resolveIssuerVerificationKey(
	issuer: IssuerKeyMaterial,
	kid?: string,
	alg?: string,
) {
	if ("jwk" in issuer) {
		return importPublicKey(issuer.jwk as JWK, alg ?? HOLDER_KEY_ALG);
	}

	const selected = kid
		? issuer.jwks.keys.find((candidate) => candidate.kid === kid)
		: issuer.jwks.keys.length === 1
			? issuer.jwks.keys[0]
			: undefined;

	if (!selected) {
		throw new WalletError(
			"Unable to resolve issuer verification key from supplied metadata",
		);
	}

	return importPublicKey(selected as JWK, alg ?? HOLDER_KEY_ALG);
}

function assertSupportedDcqlQuery(query: ParsedDcqlQuery): void {
	for (const credentialQuery of query.credentials as Array<
		Record<string, unknown>
	>) {
		if (credentialQuery.format !== "dc+sd-jwt") {
			throw new WalletError(
				`Unsupported credential format: ${credentialQuery.format}`,
			);
		}

		if (credentialQuery.multiple) {
			throw new WalletError("multiple=true is unsupported in the demo wallet");
		}

		if (credentialQuery.claim_sets) {
			throw new WalletError("claim_sets are unsupported in the demo wallet");
		}

		if (credentialQuery.trusted_authorities) {
			throw new WalletError(
				"trusted_authorities are unsupported in the demo wallet",
			);
		}

		if (
			credentialQuery.meta &&
			Object.keys(credentialQuery.meta).some((key) => key !== "vct_values")
		) {
			throw new WalletError(
				"Only meta.vct_values is supported for dc+sd-jwt queries",
			);
		}

		for (const claim of (credentialQuery.claims ?? []) as Array<
			Record<string, unknown>
		>) {
			if (claim.values) {
				throw new WalletError(
					"Claim value filters are unsupported in the demo wallet",
				);
			}

			for (const segment of (claim.path as Array<string | number | null>) ??
				[]) {
				if (typeof segment !== "string") {
					throw new WalletError(
						"Only string claim path segments are supported in the demo wallet",
					);
				}
			}
		}
	}
}

function stripReservedClaims(
	claims: Record<string, unknown>,
): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(claims).filter(
			([key]) => !RESERVED_TOP_LEVEL_CLAIMS.has(key),
		),
	);
}

function readStringClaim(value: unknown, message: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new WalletError(message);
	}

	return value;
}

function readRecordClaim(
	value: unknown,
	message: string,
): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new WalletError(message);
	}

	return value as Record<string, unknown>;
}

function claimPathsToPresentationFrame(
	paths: Array<Array<string | number | null>>,
): Record<string, boolean | Record<string, unknown>> {
	const frame: Record<string, boolean | Record<string, unknown>> = {};

	for (const path of paths) {
		let cursor: Record<string, boolean | Record<string, unknown>> = frame;
		for (const [index, segment] of path.entries()) {
			if (typeof segment !== "string") {
				throw new WalletError(
					"Only string claim path segments are supported in presentation frames",
				);
			}

			if (index === path.length - 1) {
				cursor[segment] = true;
				continue;
			}

			const next = cursor[segment];
			if (!next || typeof next !== "object" || Array.isArray(next)) {
				cursor[segment] = {};
			}

			cursor = cursor[segment] as Record<
				string,
				boolean | Record<string, unknown>
			>;
		}
	}

	return frame;
}
