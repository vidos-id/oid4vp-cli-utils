import { Command } from "commander";
import { importCredentialAction } from "./actions/import.ts";
import { listCredentialsAction } from "./actions/list.ts";
import { presentCredentialAction } from "./actions/present.ts";
import { showCredentialAction } from "./actions/show.ts";
import { printResult } from "./io.ts";

export function createProgram(): Command {
	const program = new Command()
		.name("wallet-cli")
		.description(
			"Demo wallet CLI for dc+sd-jwt import and OpenID4VP presentation",
		);

	program
		.command("import")
		.description(
			"Import an issuer-bound credential into file-backed wallet storage",
		)
		.requiredOption("--wallet-dir <dir>", "Wallet storage directory")
		.option("--credential <compact>", "Inline dc+sd-jwt credential")
		.option("--credential-file <file>", "Read dc+sd-jwt credential from file")
		.option(
			"--issuer <issuer>",
			"Issuer identifier when not using issuer metadata",
		)
		.option(
			"--issuer-metadata <json>",
			"Inline issuer metadata JSON with issuer + jwks",
		)
		.option(
			"--issuer-metadata-file <file>",
			"Read issuer metadata JSON from file",
		)
		.option("--issuer-jwks-file <file>", "Read issuer JWKS JSON from file")
		.option("--issuer-jwk-file <file>", "Read single issuer JWK JSON from file")
		.option("--output <format>", "Output format: json|pretty", "pretty")
		.action(async (options) => {
			const result = await importCredentialAction(options);
			printResult(result, options.output);
		});

	program
		.command("list")
		.description("List stored credentials from a wallet directory")
		.requiredOption("--wallet-dir <dir>", "Wallet storage directory")
		.option("--vct <vct>", "Filter credentials by vct")
		.option("--issuer <issuer>", "Filter credentials by issuer")
		.option("--output <format>", "Output format: json|pretty", "pretty")
		.action(async (options) => {
			const result = await listCredentialsAction(options);
			printResult(result, options.output);
		});

	program
		.command("show")
		.description("Show one stored credential")
		.requiredOption("--wallet-dir <dir>", "Wallet storage directory")
		.requiredOption("--credential-id <id>", "Stored credential id")
		.option("--output <format>", "Output format: json|pretty|raw", "pretty")
		.action(async (options) => {
			const result = await showCredentialAction(options);
			if (options.output === "raw") {
				process.stdout.write(`${result.credential.compactSdJwt}\n`);
				return;
			}
			printResult(result, options.output);
		});

	program
		.command("present")
		.description("Create a dcql_query-based OpenID4VP presentation")
		.requiredOption("--wallet-dir <dir>", "Wallet storage directory")
		.option(
			"--request <value>",
			"Inline OpenID4VP request JSON or oid4vp:// authorization URL",
		)
		.option(
			"--request-file <file>",
			"Read OpenID4VP request JSON or oid4vp:// authorization URL from file",
		)
		.option(
			"--credential-id <id>",
			"Limit presentation generation to one stored credential",
		)
		.option("--output <format>", "Output format: json|pretty|raw", "pretty")
		.action(async (options) => {
			const result = await presentCredentialAction(options);
			if (options.output === "raw") {
				process.stdout.write(`${result.vpToken}\n`);
				return;
			}
			printResult(result, options.output);
		});

	return program;
}
