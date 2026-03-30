import { deflateSync } from "node:zlib";
import type { JWK } from "jose";
import { SignJWT } from "jose";
import {
	allocateCredentialStatusInputSchema,
	type CreateStatusListInput,
	type CredentialStatus,
	createStatusListInputSchema,
	type StatusListBits,
	type StatusListRecord,
	statusListRecordSchema,
	type TokenStatusValue,
	updateCredentialStatusInputSchema,
} from "./schemas.ts";

const maxStatusValue = (bits: StatusListBits) => (1 << bits) - 1;

function assertStatusValueFits(bits: StatusListBits, value: TokenStatusValue) {
	if (value > maxStatusValue(bits)) {
		throw new Error(
			`Status value ${value} does not fit in a ${bits}-bit status list`,
		);
	}
}

export function createStatusList(
	input: CreateStatusListInput,
): StatusListRecord {
	const parsed = createStatusListInputSchema.parse(input);
	return statusListRecordSchema.parse({
		...parsed,
		statuses: [],
	});
}

export function allocateCredentialStatus(input: {
	statusList: StatusListRecord;
	status?: TokenStatusValue;
}): {
	credentialStatus: CredentialStatus;
	updatedStatusList: StatusListRecord;
} {
	const parsed = allocateCredentialStatusInputSchema.parse(input);
	assertStatusValueFits(parsed.statusList.bits, parsed.status);
	const idx = parsed.statusList.statuses.length;
	const updatedStatusList = statusListRecordSchema.parse({
		...parsed.statusList,
		statuses: [...parsed.statusList.statuses, parsed.status],
	});
	return {
		credentialStatus: {
			status_list: {
				idx,
				uri: parsed.statusList.uri,
			},
		},
		updatedStatusList,
	};
}

export function updateCredentialStatus(input: {
	statusList: StatusListRecord;
	idx: number;
	status: TokenStatusValue;
}): StatusListRecord {
	const parsed = updateCredentialStatusInputSchema.parse(input);
	assertStatusValueFits(parsed.statusList.bits, parsed.status);
	if (parsed.idx >= parsed.statusList.statuses.length) {
		throw new Error(`Status list index ${parsed.idx} is out of bounds`);
	}
	const statuses = [...parsed.statusList.statuses];
	statuses[parsed.idx] = parsed.status;
	return statusListRecordSchema.parse({
		...parsed.statusList,
		statuses,
	});
}

export function encodeStatusList(statusList: StatusListRecord): {
	bits: StatusListBits;
	lst: string;
	aggregation_uri?: string;
} {
	const parsed = statusListRecordSchema.parse(statusList);
	const packed = packStatuses(parsed.statuses, parsed.bits);
	return {
		bits: parsed.bits,
		lst: deflateSync(packed).toString("base64url"),
		aggregation_uri: parsed.aggregation_uri,
	};
}

export async function createStatusListJwt(input: {
	issuer: string;
	signingKey: {
		alg: string;
		privateKey: CryptoKey;
		publicJwk: JWK;
	};
	statusList: StatusListRecord;
	now: () => number;
}): Promise<string> {
	const payload = encodeStatusList(input.statusList);
	const claims: Record<string, unknown> = {
		iss: input.issuer,
		status_list: payload,
	};
	if (input.statusList.ttl) {
		claims.ttl = input.statusList.ttl;
	}
	const jwt = new SignJWT(claims)
		.setProtectedHeader({
			alg: input.signingKey.alg,
			typ: "statuslist+jwt",
			kid: input.signingKey.publicJwk.kid,
			x5c: input.signingKey.publicJwk.x5c,
		})
		.setSubject(input.statusList.uri)
		.setIssuedAt(input.now());
	if (input.statusList.expiresAt) {
		jwt.setExpirationTime(input.statusList.expiresAt);
	}

	return jwt.sign(input.signingKey.privateKey);
}

function packStatuses(
	statuses: TokenStatusValue[],
	bits: StatusListBits,
): Uint8Array {
	const byteLength = Math.ceil((statuses.length * bits) / 8);
	const output = new Uint8Array(byteLength);
	for (const [idx, status] of statuses.entries()) {
		assertStatusValueFits(bits, status);
		const bitOffset = idx * bits;
		const byteIndex = Math.floor(bitOffset / 8);
		const intraByteOffset = bitOffset % 8;
		output[byteIndex] = (output[byteIndex] ?? 0) | (status << intraByteOffset);
	}
	return output;
}
