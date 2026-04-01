type HolderKeyLike = {
	id: string;
	algorithm?: string;
};

type CredentialLike = {
	id: string;
	issuer: string;
	vct: string;
	claims: Record<string, unknown>;
	compactSdJwt: string;
	status?: {
		status_list?: {
			uri: string;
			idx: number;
		};
	};
};

type ResolvedCredentialStatusLike = {
	status: {
		label: string;
		isValid: boolean;
		value: number;
	};
	statusReference: {
		uri: string;
		idx: number;
	};
	statusList: {
		ttl?: number;
	};
};

type MatchedCredentialLike = {
	credentialId: string;
	issuer: string;
	vct: string;
};

type PresentationSummaryLike = {
	matchedCredentials: MatchedCredentialLike[];
	submitted: boolean;
	submission?: unknown;
};

export function formatInitResult(input: {
	walletDir: string;
	holderKey: HolderKeyLike;
	imported: boolean;
}): string {
	const source = input.imported ? "imported" : "generated";
	return [
		`Initialized wallet at ${input.walletDir}`,
		`Holder key: ${input.holderKey.id} (${input.holderKey.algorithm ?? "unknown"}, ${source})`,
	].join("\n");
}

export function formatCredentialSummary(
	action: "Imported" | "Received",
	credential: CredentialLike,
): string {
	return [
		`${action} credential ${credential.id}`,
		`VCT: ${credential.vct}`,
		`Issuer: ${credential.issuer}`,
	].join("\n");
}

export function formatCredentialList(credentials: CredentialLike[]): string {
	if (credentials.length === 0) {
		return "0 credentials found";
	}

	const lines = [
		`${credentials.length} credential${credentials.length === 1 ? "" : "s"} found`,
	];
	for (const credential of credentials) {
		lines.push(`${credential.id} | ${credential.vct} | ${credential.issuer}`);
	}
	return lines.join("\n");
}

export function formatCredentialDetails(input: {
	credential: CredentialLike;
	status: ResolvedCredentialStatusLike | null;
	statusWarning?: string;
}): string {
	const { credential, status, statusWarning } = input;
	const lines = [
		"Credential",
		`ID: ${credential.id}`,
		`Issuer: ${credential.issuer}`,
		`VCT: ${credential.vct}`,
		"",
		"Claims",
	];

	const claimEntries = Object.entries(credential.claims);
	if (claimEntries.length === 0) {
		lines.push("none");
	} else {
		for (const [key, value] of claimEntries) {
			lines.push(`${key}: ${formatValue(value)}`);
		}
	}

	lines.push("", "Status");
	if (status) {
		lines.push(`State: ${status.status.label}`);
		lines.push(`Valid: ${status.status.isValid ? "yes" : "no"}`);
		lines.push(`Value: ${status.status.value}`);
		lines.push(
			`Reference: ${status.statusReference.uri}#${status.statusReference.idx}`,
		);
		if (status.statusList.ttl !== undefined) {
			lines.push(`TTL: ${status.statusList.ttl}`);
		}
	} else if (credential.status?.status_list) {
		lines.push("State: unresolved");
		lines.push(
			`Reference: ${credential.status.status_list.uri}#${credential.status.status_list.idx}`,
		);
		if (statusWarning) {
			lines.push(`Warning: ${statusWarning}`);
		}
	} else {
		lines.push("State: not present");
	}

	return lines.join("\n");
}

export function formatPresentationSummary(
	result: PresentationSummaryLike,
): string {
	const lines = ["Presentation created"];
	if (result.matchedCredentials.length === 0) {
		lines.push("Matched credentials: none");
	} else {
		lines.push("Matched credentials:");
		for (const credential of result.matchedCredentials) {
			lines.push(
				`${credential.credentialId} | ${credential.vct} | ${credential.issuer}`,
			);
		}
	}
	lines.push(`Submitted: ${result.submitted ? "yes" : "no"}`);
	if (result.submission !== undefined) {
		lines.push(`Submission response: ${formatValue(result.submission)}`);
	}
	return lines.join("\n");
}

export function formatDeleteCredentialSummary(credentialId: string): string {
	return `Deleted credential ${credentialId}`;
}

export function formatDeleteAllCredentialsSummary(deleted: number): string {
	return `Deleted ${deleted} credential${deleted === 1 ? "" : "s"}`;
}

export function formatDeleteWalletSummary(walletDir: string): string {
	return `Deleted wallet at ${walletDir}`;
}

function formatValue(value: unknown): string {
	if (typeof value === "string") {
		return value;
	}
	if (typeof value === "number" || typeof value === "boolean") {
		return String(value);
	}
	if (value === null || value === undefined) {
		return String(value);
	}
	return JSON.stringify(value);
}
