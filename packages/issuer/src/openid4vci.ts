import type { IssuerConfigInput } from "./schemas.ts";
import {
	type CredentialOffer,
	type CredentialOfferUri,
	credentialOfferSchema,
	credentialOfferUriSchema,
	type IssuerMetadataPayload,
	issuerConfigSchema,
	issuerMetadataSchema,
} from "./schemas.ts";

const OPENID_CREDENTIAL_OFFER_WELL_KNOWN =
	"/.well-known/openid-credential-issuer";

export function createIssuerMetadata(
	config: IssuerConfigInput,
): IssuerMetadataPayload {
	const parsed = issuerConfigSchema.parse(config);
	const tokenEndpoint =
		parsed.endpoints?.token ?? new URL("/token", parsed.issuer).toString();
	const credentialEndpoint =
		parsed.endpoints?.credential ??
		new URL("/credential", parsed.issuer).toString();
	const nonceEndpoint =
		parsed.endpoints?.nonce ?? new URL("/nonce", parsed.issuer).toString();

	return issuerMetadataSchema.parse({
		credential_issuer: parsed.issuer,
		token_endpoint: tokenEndpoint,
		credential_endpoint: credentialEndpoint,
		nonce_endpoint: nonceEndpoint,
		jwks: {
			keys: [parsed.signingKey.publicJwk],
		},
		credential_configurations_supported: Object.fromEntries(
			Object.entries(parsed.credentialConfigurationsSupported).map(
				([id, entry]) => [
					id,
					{
						format: entry.format,
						vct: entry.vct,
						scope: entry.scope ?? id,
						proof_types_supported: {
							jwt: {
								proof_signing_alg_values_supported:
									entry.proof_signing_alg_values_supported,
							},
						},
						cryptographic_binding_methods_supported: ["jwk"],
						credential_signing_alg_values_supported: [parsed.signingKey.alg],
					},
				],
			),
		),
	});
}

export function serializeCredentialOfferUri(
	offer: CredentialOffer,
): CredentialOfferUri {
	const parsed = credentialOfferSchema.parse(offer);
	const url = new URL("openid-credential-offer://");
	url.searchParams.set("credential_offer", JSON.stringify(parsed));
	return credentialOfferUriSchema.parse(url.toString());
}

export function serializeCredentialOfferReferenceUri(
	credentialOfferUrl: string,
): CredentialOfferUri {
	const parsed = new URL(credentialOfferUrl).toString();
	const url = new URL("openid-credential-offer://");
	url.searchParams.set("credential_offer_uri", parsed);
	return credentialOfferUriSchema.parse(url.toString());
}

export function getCredentialIssuerMetadataUrl(
	credentialIssuer: string,
): string {
	const issuerUrl = new URL(credentialIssuer);
	const issuerPath = issuerUrl.pathname === "/" ? "" : issuerUrl.pathname;
	return new URL(
		`${OPENID_CREDENTIAL_OFFER_WELL_KNOWN}${issuerPath}`,
		issuerUrl.origin,
	).toString();
}
