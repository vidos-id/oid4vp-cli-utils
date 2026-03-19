import { z } from "zod";

import {
	type OpenId4VpRequestInput,
	OpenId4VpRequestSchema,
} from "./schemas.ts";
import { WalletError } from "./wallet.ts";

const oid4vpAuthorizationUrlSchema = z.string().min(1);

const unsupportedOid4VpParams = new Map([
	[
		"request",
		"Signed request objects are unsupported; pass request fields by value in the oid4vp:// URL",
	],
	["request_uri", "request_uri is unsupported in the demo wallet"],
	[
		"request_uri_method",
		"request_uri_method is unsupported in the demo wallet",
	],
	["scope", "scope-encoded queries are unsupported"],
	["presentation_definition", "Presentation Exchange is unsupported"],
]);

export function parseOid4VpAuthorizationUrl(
	input: string,
): OpenId4VpRequestInput {
	const value = oid4vpAuthorizationUrlSchema.parse(input).trim();

	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw new WalletError("Invalid oid4vp authorization URL");
	}

	if (url.protocol !== "oid4vp:") {
		throw new WalletError("Authorization URL must use the oid4vp:// scheme");
	}

	for (const [param, message] of unsupportedOid4VpParams) {
		if (url.searchParams.has(param)) {
			throw new WalletError(message);
		}
	}

	const dcqlQueryRaw = getSingleSearchParam(url, "dcql_query");
	let dcqlQuery: unknown;
	try {
		dcqlQuery = JSON.parse(dcqlQueryRaw);
	} catch {
		throw new WalletError("dcql_query must be valid JSON in the oid4vp:// URL");
	}

	return OpenId4VpRequestSchema.parse({
		client_id: getSingleSearchParam(url, "client_id"),
		nonce: getSingleSearchParam(url, "nonce"),
		response_type: getOptionalSingleSearchParam(url, "response_type"),
		dcql_query: dcqlQuery,
	});
}

function getSingleSearchParam(url: URL, key: string): string {
	const values = url.searchParams.getAll(key);
	if (values.length === 0 || values[0]?.length === 0) {
		throw new WalletError(`Authorization URL is missing ${key}`);
	}
	if (values.length > 1) {
		throw new WalletError(`Authorization URL must include only one ${key}`);
	}
	return values[0] as string;
}

function getOptionalSingleSearchParam(
	url: URL,
	key: string,
): string | undefined {
	const values = url.searchParams.getAll(key);
	if (values.length === 0) {
		return undefined;
	}
	if (values.length > 1) {
		throw new WalletError(`Authorization URL must include only one ${key}`);
	}
	return values[0] || undefined;
}
