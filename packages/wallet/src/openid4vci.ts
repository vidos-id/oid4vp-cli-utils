import { z } from "zod";
import { createOpenId4VciProofJwt } from "./crypto.ts";
import type { StoredCredentialRecord } from "./schemas.ts";
import { type Wallet, WalletError } from "./wallet.ts";

const PRE_AUTHORIZED_GRANT_TYPE =
	"urn:ietf:params:oauth:grant-type:pre-authorized_code";
const OPENID_CREDENTIAL_OFFER_WELL_KNOWN =
	"/.well-known/openid-credential-issuer";

const jwkSchema = z
	.object({
		kty: z.string().min(1),
		kid: z.string().min(1).optional(),
		alg: z.string().min(1).optional(),
		crv: z.string().min(1).optional(),
		x: z.string().min(1).optional(),
		y: z.string().min(1).optional(),
		d: z.string().min(1).optional(),
		n: z.string().min(1).optional(),
		e: z.string().min(1).optional(),
		x5c: z.array(z.string().min(1)).optional(),
	})
	.catchall(z.unknown());

const credentialOfferSchema = z.object({
	credential_issuer: z.string().url(),
	credential_configuration_ids: z.array(z.string().min(1)).length(1),
	grants: z.object({
		[PRE_AUTHORIZED_GRANT_TYPE]: z.object({
			"pre-authorized_code": z.string().min(1),
			tx_code: z.never().optional(),
		}),
	}),
});

const credentialOfferReferenceSchema = z.object({
	credential_offer_uri: z.string().url(),
});

const issuerMetadataSchema = z.object({
	credential_issuer: z.string().url(),
	token_endpoint: z.string().url(),
	credential_endpoint: z.string().url(),
	nonce_endpoint: z.string().url().optional(),
	jwks: z.object({
		keys: z.array(jwkSchema).min(1),
	}),
	credential_configurations_supported: z.record(
		z.string(),
		z.object({
			format: z.literal("dc+sd-jwt"),
			vct: z.string().min(1),
			scope: z.string().min(1),
			proof_types_supported: z.object({
				jwt: z.object({
					proof_signing_alg_values_supported: z.array(z.string().min(1)).min(1),
				}),
			}),
			credential_signing_alg_values_supported: z
				.array(z.string().min(1))
				.min(1),
		}),
	),
});

const tokenResponseSchema = z.object({
	access_token: z.string().min(1),
	token_type: z.literal("Bearer"),
	expires_in: z.number().int().positive(),
	credential_configuration_id: z.string().min(1),
	c_nonce: z.string().min(1).optional(),
	c_nonce_expires_in: z.number().int().positive().optional(),
});

const nonceResponseSchema = z.object({
	c_nonce: z.string().min(1),
	c_nonce_expires_in: z.number().int().positive(),
});

const credentialResponseSchema = z.object({
	format: z.literal("dc+sd-jwt"),
	credential: z.string().min(1),
	c_nonce: z.string().min(1).optional(),
	c_nonce_expires_in: z.number().int().positive().optional(),
});

export type OpenId4VciCredentialOffer = z.infer<typeof credentialOfferSchema>;
export type OpenId4VciIssuerMetadata = z.infer<typeof issuerMetadataSchema>;

export function parseCredentialOffer(
	input: unknown,
): OpenId4VciCredentialOffer {
	if (typeof input === "string") {
		const trimmed = input.trim();
		if (trimmed.startsWith("openid-credential-offer://")) {
			return parseCredentialOfferUri(trimmed);
		}
		try {
			return credentialOfferSchema.parse(JSON.parse(trimmed));
		} catch (error) {
			if (error instanceof z.ZodError) {
				throw new WalletError("Unsupported credential offer input");
			}
			throw new WalletError("Credential offer JSON must be valid JSON");
		}
	}

	try {
		return credentialOfferSchema.parse(input);
	} catch {
		throw new WalletError("Unsupported credential offer input");
	}
}

export async function fetchIssuerMetadata(
	credentialIssuer: string,
	options?: { fetch?: typeof fetch },
): Promise<OpenId4VciIssuerMetadata> {
	const doFetch = options?.fetch ?? fetch;
	const response = await doFetch(
		getCredentialIssuerMetadataUrl(credentialIssuer),
		{
			headers: { accept: "application/json" },
		},
	);
	const json = await parseJsonResponse(response, "issuer metadata");
	const metadata = issuerMetadataSchema.parse(json);
	if (metadata.credential_issuer !== credentialIssuer) {
		throw new WalletError("Issuer metadata credential_issuer mismatch");
	}
	return metadata;
}

export async function receiveCredentialFromOffer(
	wallet: Wallet,
	offerInput: unknown,
	options?: { fetch?: typeof fetch },
): Promise<StoredCredentialRecord> {
	const doFetch = options?.fetch ?? fetch;
	const offer = await resolveCredentialOffer(offerInput, doFetch);
	const metadata = await fetchIssuerMetadata(offer.credential_issuer, {
		fetch: doFetch,
	});
	const credentialConfigurationId = offer.credential_configuration_ids[0];
	if (!credentialConfigurationId) {
		throw new WalletError(
			"Credential offer must contain one credential configuration",
		);
	}
	const configuration =
		metadata.credential_configurations_supported[credentialConfigurationId];
	if (!configuration) {
		throw new WalletError(
			`Issuer metadata does not support ${credentialConfigurationId}`,
		);
	}
	if (!configuration.proof_types_supported.jwt) {
		throw new WalletError("Issuer does not support jwt proofs");
	}

	const tokenResponse = await exchangePreAuthorizedCode(
		metadata.token_endpoint,
		offer.grants[PRE_AUTHORIZED_GRANT_TYPE]["pre-authorized_code"],
		doFetch,
	);
	const nonce =
		tokenResponse.c_nonce ??
		(await fetchNonce(metadata.nonce_endpoint, doFetch)).c_nonce;
	const holderKey = await wallet.getOrCreateHolderKey();
	const proofJwt = await createOpenId4VciProofJwt({
		holderPrivateJwk: holderKey.privateJwk as never,
		holderPublicJwk: holderKey.publicJwk as never,
		aud: metadata.credential_issuer,
		nonce,
		alg: holderKey.algorithm,
	});
	if (
		!configuration.proof_types_supported.jwt.proof_signing_alg_values_supported.includes(
			holderKey.algorithm,
		)
	) {
		throw new WalletError(
			`Issuer does not support holder proof algorithm ${holderKey.algorithm}`,
		);
	}
	const credentialResponse = await requestCredential(
		metadata.credential_endpoint,
		tokenResponse.access_token,
		{
			format: "dc+sd-jwt",
			credential_configuration_id: credentialConfigurationId,
			proofs: {
				jwt: [
					{
						proof_type: "jwt",
						jwt: proofJwt,
					},
				],
			},
		},
		doFetch,
	);

	return wallet.importCredential({
		credential: credentialResponse.credential,
		issuer: {
			issuer: metadata.credential_issuer,
			jwks: metadata.jwks,
		},
	});
}

async function resolveCredentialOffer(
	input: unknown,
	doFetch: typeof fetch,
): Promise<OpenId4VciCredentialOffer> {
	if (typeof input === "string") {
		const trimmed = input.trim();
		if (trimmed.startsWith("openid-credential-offer://")) {
			const parsed = parseCredentialOfferUriOrReference(trimmed);
			if ("credential_offer_uri" in parsed) {
				return fetchCredentialOffer(parsed.credential_offer_uri, doFetch);
			}
			return parsed;
		}
	}

	return parseCredentialOffer(input);
}

function parseCredentialOfferUri(input: string): OpenId4VciCredentialOffer {
	const parsed = parseCredentialOfferUriOrReference(input);
	if ("credential_offer_uri" in parsed) {
		throw new WalletError(
			"Credential offer URI references a remote offer; fetch it via receiveCredentialFromOffer",
		);
	}
	return parsed;
}

function parseCredentialOfferUriOrReference(
	input: string,
): OpenId4VciCredentialOffer | z.infer<typeof credentialOfferReferenceSchema> {
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new WalletError("Invalid credential offer URI");
	}
	if (url.protocol !== "openid-credential-offer:") {
		throw new WalletError(
			"Credential offer URI must use the openid-credential-offer:// scheme",
		);
	}
	const offerUri = getSingleSearchParam(url, "credential_offer_uri");
	if (offerUri) {
		try {
			return credentialOfferReferenceSchema.parse({
				credential_offer_uri: offerUri,
			});
		} catch {
			throw new WalletError(
				"Credential offer URI contains an invalid credential_offer_uri",
			);
		}
	}
	const encodedOffer = getSingleSearchParam(url, "credential_offer");
	if (!encodedOffer) {
		throw new WalletError("Credential offer URI is missing credential_offer");
	}
	try {
		return credentialOfferSchema.parse(JSON.parse(encodedOffer));
	} catch {
		throw new WalletError(
			"Credential offer URI contains invalid credential_offer JSON",
		);
	}
}

async function fetchCredentialOffer(endpoint: string, doFetch: typeof fetch) {
	const response = await doFetch(endpoint, {
		headers: { accept: "application/json" },
	});
	const json = await parseJsonResponse(response, "credential offer");
	return credentialOfferSchema.parse(json);
}

function getCredentialIssuerMetadataUrl(credentialIssuer: string): string {
	const issuerUrl = new URL(credentialIssuer);
	const issuerPath = issuerUrl.pathname === "/" ? "" : issuerUrl.pathname;
	return new URL(
		`${OPENID_CREDENTIAL_OFFER_WELL_KNOWN}${issuerPath}`,
		issuerUrl.origin,
	).toString();
}

async function exchangePreAuthorizedCode(
	endpoint: string,
	preAuthorizedCode: string,
	doFetch: typeof fetch,
) {
	const response = await doFetch(endpoint, {
		method: "POST",
		headers: {
			accept: "application/json",
			"content-type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams({
			grant_type: PRE_AUTHORIZED_GRANT_TYPE,
			"pre-authorized_code": preAuthorizedCode,
		}),
	});
	return tokenResponseSchema.parse(
		await parseJsonResponse(response, "token exchange"),
	);
}

async function fetchNonce(endpoint: string | undefined, doFetch: typeof fetch) {
	if (!endpoint) {
		throw new WalletError("Issuer metadata is missing nonce_endpoint");
	}
	const response = await doFetch(endpoint, {
		method: "POST",
		headers: { accept: "application/json" },
	});
	return nonceResponseSchema.parse(await parseJsonResponse(response, "nonce"));
}

async function requestCredential(
	endpoint: string,
	accessToken: string,
	body: Record<string, unknown>,
	doFetch: typeof fetch,
) {
	const response = await doFetch(endpoint, {
		method: "POST",
		headers: {
			accept: "application/json",
			authorization: `Bearer ${accessToken}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
	return credentialResponseSchema.parse(
		await parseJsonResponse(response, "credential request"),
	);
}

async function parseJsonResponse(
	response: Response,
	label: string,
): Promise<unknown> {
	let payload: unknown;
	try {
		payload = (await response.json()) as unknown;
	} catch {
		throw new WalletError(`Failed to parse ${label} response`);
	}
	if (!response.ok) {
		const message =
			payload && typeof payload === "object" && !Array.isArray(payload)
				? ((payload as Record<string, unknown>).error_description ??
					(payload as Record<string, unknown>).error)
				: undefined;
		throw new WalletError(
			`${label} failed with status ${response.status}${typeof message === "string" ? `: ${message}` : ""}`,
		);
	}
	return payload;
}

function getSingleSearchParam(url: URL, key: string): string | undefined {
	const values = url.searchParams.getAll(key);
	if (values.length === 0) {
		return undefined;
	}
	if (values.length > 1) {
		throw new WalletError(`Credential offer URI must include only one ${key}`);
	}
	return values[0] || undefined;
}
