import { createInterface } from "node:readline/promises";
import {
	type OpenId4VpRequestInput,
	OpenId4VpRequestSchema,
	parseOid4VpAuthorizationUrl,
	type QueryCredentialMatches,
	Wallet,
	type WalletStorage,
} from "wallet";
import { readTextInput } from "../io.ts";
import { presentOptionsSchema } from "../schemas.ts";
import { SelectedCredentialStorage } from "../selected-storage.ts";
import { FileSystemWalletStorage } from "../storage.ts";

export async function presentCredentialAction(rawOptions: unknown) {
	const options = presentOptionsSchema.parse(rawOptions);
	const request = parsePresentationRequest(
		await readTextInput(options.request, options.requestFile),
	);
	const storage = new FileSystemWalletStorage(options.walletDir);
	const wallet = options.credentialId
		? await createSelectedWallet(storage, options.credentialId)
		: new Wallet(storage);
	const selectedCredentials = options.credentialId
		? undefined
		: await maybeSelectCredentials(
				wallet,
				request,
				(rawOptions as { prompt?: CredentialPrompt }).prompt,
			);
	const presentation = await wallet.createPresentation(request, {
		selectedCredentials,
	});
	return presentation;
}

type CredentialPrompt = (queryMatch: QueryCredentialMatches) => Promise<string>;

function parsePresentationRequest(value: string): OpenId4VpRequestInput {
	const trimmed = value.trim();
	if (trimmed.startsWith("oid4vp:")) {
		return parseOid4VpAuthorizationUrl(trimmed);
	}

	return OpenId4VpRequestSchema.parse(
		JSON.parse(trimmed) as OpenId4VpRequestInput,
	);
}

async function maybeSelectCredentials(
	wallet: Wallet,
	request: OpenId4VpRequestInput,
	prompt?: CredentialPrompt,
): Promise<Record<string, string> | undefined> {
	const inspected = await wallet.inspectDcqlQuery(request);
	const ambiguousQueries = inspected.queries.filter(
		(queryMatch) => queryMatch.credentials.length > 1,
	);

	if (ambiguousQueries.length === 0) {
		return undefined;
	}

	const selections: Record<string, string> = {};
	for (const queryMatch of ambiguousQueries) {
		selections[queryMatch.queryId] = prompt
			? await prompt(queryMatch)
			: await promptForCredentialSelection(queryMatch);
	}

	return selections;
}

async function promptForCredentialSelection(
	queryMatch: QueryCredentialMatches,
): Promise<string> {
	if (!process.stdin.isTTY || !process.stdout.isTTY) {
		throw new Error(
			`Multiple credentials match query ${queryMatch.queryId}; rerun in a terminal or pass --credential-id`,
		);
	}

	process.stdout.write(
		`Multiple credentials match query ${queryMatch.queryId}:\n`,
	);
	for (const [index, credential] of queryMatch.credentials.entries()) {
		process.stdout.write(
			`${index + 1}. ${credential.credentialId} | ${credential.vct} | ${credential.issuer} | ${formatClaimPreview(credential.claims)}\n`,
		);
	}

	const rl = createInterface({ input: process.stdin, output: process.stdout });
	try {
		while (true) {
			const answer = (
				await rl.question(
					`Select credential [1-${queryMatch.credentials.length}]: `,
				)
			).trim();
			const selectedIndex = Number.parseInt(answer, 10) - 1;
			const selected = queryMatch.credentials[selectedIndex];
			if (selected) {
				return selected.credentialId;
			}
			process.stdout.write("Enter a valid number.\n");
		}
	} finally {
		rl.close();
	}
}

function formatClaimPreview(claims: Record<string, unknown>): string {
	const preview = Object.entries(claims)
		.slice(0, 2)
		.map(([key, value]) => `${key}=${formatClaimValue(value)}`)
		.join(", ");
	return preview.length > 0 ? preview : "no disclosed claims";
}

function formatClaimValue(value: unknown): string {
	if (typeof value === "string" || typeof value === "number") {
		return String(value);
	}
	if (typeof value === "boolean") {
		return value ? "true" : "false";
	}
	if (value && typeof value === "object") {
		return JSON.stringify(value);
	}
	return "?";
}

async function createSelectedWallet(
	storage: WalletStorage,
	credentialId: string,
): Promise<Wallet> {
	const credential = await storage.getCredential(credentialId);
	if (!credential) {
		throw new Error(`Credential ${credentialId} not found`);
	}
	return new Wallet(new SelectedCredentialStorage(storage, credential));
}
