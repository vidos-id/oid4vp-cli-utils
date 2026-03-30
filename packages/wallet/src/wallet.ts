import { inflateSync } from "node:zlib";
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
	type CredentialStatus,
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

export type TokenStatusLabel =
	| "VALID"
	| "INVALID"
	| "SUSPENDED"
	| "APPLICATION_SPECIFIC"
	| "UNASSIGNED";

export type ResolvedCredentialStatus = {
	credentialId: string;
	statusReference: CredentialStatus["status_list"];
	status: {
		value: number;
		label: TokenStatusLabel;
		isValid: boolean;
	};
	statusList: {
		uri: string;
		bits: 1 | 2 | 4 | 8;
		iat: number;
		exp?: number;
		ttl?: number;
		aggregationUri?: string;
		jwt: string;
	};
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

	async getCredentialStatus(
		credentialId: string,
		options?: { fetch?: typeof fetch },
	): Promise<ResolvedCredentialStatus | null> {
		const credential = await this.storage.getCredential(credentialId);
		if (!credential) {
			throw new WalletError(`Credential ${credentialId} not found`);
		}
		if (!credential.status?.status_list) {
			return null;
		}

		const doFetch = options?.fetch ?? fetch;
		const statusJwt = await fetchStatusListJwt(
			credential.status.status_list.uri,
			doFetch,
		);
		const protectedHeader = decodeProtectedHeader(statusJwt);
		const issuerKeyMaterial =
			credential.issuerKeyMaterial ??
			(await fetchIssuerKeyMaterial(credential.issuer, doFetch));
		const verificationKey = await resolveIssuerVerificationKey(
			issuerKeyMaterial,
			protectedHeader.kid,
			typeof protectedHeader.alg === "string" ? protectedHeader.alg : undefined,
		);
		const verified = await jwtVerify(statusJwt, verificationKey, {
			typ: "statuslist+jwt",
			subject: credential.status.status_list.uri,
		});
		const payload = parseStatusListTokenPayload(verified.payload);
		const value = readStatusValue(
			payload.status_list.lst,
			payload.status_list.bits,
			credential.status.status_list.idx,
		);

		return {
			credentialId: credential.id,
			statusReference: credential.status.status_list,
			status: {
				value,
				label: labelForTokenStatus(value),
				isValid: value === 0,
			},
			statusList: {
				uri: credential.status.status_list.uri,
				bits: payload.status_list.bits,
				iat: payload.iat,
				exp: payload.exp,
				ttl: payload.ttl,
				aggregationUri: payload.status_list.aggregation_uri,
				jwt: statusJwt,
			},
		};
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
			status: parseCredentialStatus(payload.status),
			issuerKeyMaterial: parsedInput.issuer,
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

async function fetchStatusListJwt(uri: string, doFetch: typeof fetch) {
	const response = await doFetch(uri, {
		headers: {
			accept: "application/statuslist+jwt, application/jwt, text/plain",
		},
	});
	if (!response.ok) {
		throw new WalletError(
			`Status list fetch failed with status ${response.status}`,
		);
	}
	const payload = (await response.text()).trim();
	if (!payload) {
		throw new WalletError("Status list response is empty");
	}
	return payload;
}

async function fetchIssuerKeyMaterial(
	issuer: string,
	doFetch: typeof fetch,
): Promise<IssuerKeyMaterial> {
	const response = await doFetch(getCredentialIssuerMetadataUrl(issuer), {
		headers: { accept: "application/json" },
	});
	if (!response.ok) {
		throw new WalletError(
			`Issuer metadata fetch failed with status ${response.status}`,
		);
	}
	let payload: unknown;
	try {
		payload = (await response.json()) as unknown;
	} catch {
		throw new WalletError("Failed to parse issuer metadata response");
	}
	const parsed = readRecordClaim(
		payload,
		"Issuer metadata must be a JSON object",
	);
	return {
		issuer,
		jwks: readRecordClaim(parsed.jwks, "Issuer metadata is missing jwks") as {
			keys: Array<Record<string, unknown>>;
		},
	};
}

function getCredentialIssuerMetadataUrl(credentialIssuer: string): string {
	const issuerUrl = new URL(credentialIssuer);
	const issuerPath = issuerUrl.pathname === "/" ? "" : issuerUrl.pathname;
	return new URL(
		`/.well-known/openid-credential-issuer${issuerPath}`,
		issuerUrl.origin,
	).toString();
}

function parseCredentialStatus(value: unknown): CredentialStatus | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return undefined;
	}
	const status = value as Record<string, unknown>;
	const statusList = status.status_list;
	if (
		!statusList ||
		typeof statusList !== "object" ||
		Array.isArray(statusList)
	) {
		return undefined;
	}
	const parsedStatusList = statusList as Record<string, unknown>;
	if (
		typeof parsedStatusList.idx !== "number" ||
		!Number.isInteger(parsedStatusList.idx) ||
		parsedStatusList.idx < 0 ||
		typeof parsedStatusList.uri !== "string" ||
		parsedStatusList.uri.length === 0
	) {
		return undefined;
	}
	return {
		status_list: {
			idx: parsedStatusList.idx,
			uri: parsedStatusList.uri,
		},
	};
}

function parseStatusListTokenPayload(payload: Record<string, unknown>) {
	const sub = readStringClaim(payload.sub, "Status list token is missing sub");
	const iat = readIntegerClaim(payload.iat, "Status list token is missing iat");
	const exp =
		payload.exp === undefined
			? undefined
			: readIntegerClaim(
					payload.exp,
					"Status list token exp must be an integer",
				);
	const ttl =
		payload.ttl === undefined
			? undefined
			: readPositiveIntegerClaim(
					payload.ttl,
					"Status list token ttl must be a positive integer",
				);
	const statusList = readRecordClaim(
		payload.status_list,
		"Status list token is missing status_list",
	);
	const bits = readStatusListBits(statusList.bits);
	const lst = readStringClaim(
		statusList.lst,
		"Status list token is missing lst",
	);
	const aggregation_uri =
		statusList.aggregation_uri === undefined
			? undefined
			: readStringClaim(
					statusList.aggregation_uri,
					"Status list aggregation_uri must be a string",
				);
	return {
		sub,
		iat,
		exp,
		ttl,
		status_list: {
			bits,
			lst,
			aggregation_uri,
		},
	};
}

function readStatusValue(
	lst: string,
	bits: 1 | 2 | 4 | 8,
	idx: number,
): number {
	let bytes: Uint8Array;
	try {
		bytes = inflateSync(Buffer.from(lst, "base64url"));
	} catch {
		throw new WalletError("Failed to decode status list payload");
	}
	const bitOffset = idx * bits;
	const byteIndex = Math.floor(bitOffset / 8);
	const intraByteOffset = bitOffset % 8;
	const selectedByte = bytes[byteIndex];
	if (selectedByte === undefined) {
		throw new WalletError(`Status list index ${idx} is out of bounds`);
	}
	return (selectedByte >> intraByteOffset) & ((1 << bits) - 1);
}

function readStatusListBits(value: unknown): 1 | 2 | 4 | 8 {
	if (value === 1 || value === 2 || value === 4 || value === 8) {
		return value;
	}
	throw new WalletError("Status list bits must be one of 1, 2, 4, or 8");
}

function readIntegerClaim(value: unknown, message: string): number {
	if (typeof value !== "number" || !Number.isInteger(value)) {
		throw new WalletError(message);
	}
	return value;
}

function readPositiveIntegerClaim(value: unknown, message: string): number {
	const parsed = readIntegerClaim(value, message);
	if (parsed <= 0) {
		throw new WalletError(message);
	}
	return parsed;
}

function labelForTokenStatus(value: number): TokenStatusLabel {
	if (value === 0) {
		return "VALID";
	}
	if (value === 1) {
		return "INVALID";
	}
	if (value === 2) {
		return "SUSPENDED";
	}
	if (value === 3 || (value >= 12 && value <= 15)) {
		return "APPLICATION_SPECIFIC";
	}
	return "UNASSIGNED";
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
