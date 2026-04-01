import { stdout } from "node:process";
import type { PromptSession } from "../prompts.ts";
import { listCredentialsAction } from "./list.ts";

export async function chooseCredentialId(
	prompt: PromptSession,
	walletDir: string,
): Promise<string | null> {
	const list = await listCredentialsAction({ walletDir });
	if (list.credentials.length === 0) {
		stdout.write("0 credentials found\n\n");
		return null;
	}

	return prompt.choose(
		"Select a credential",
		list.credentials.map((credential) => ({
			label: `${credential.id} | ${credential.vct} | ${credential.issuer}`,
			value: credential.id,
		})),
	);
}
