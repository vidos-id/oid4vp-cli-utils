import { Command } from "commander";
import { createGrantAction } from "./actions/create-grant.ts";
import { createOfferAction } from "./actions/create-offer.ts";
import { generateTrustMaterialAction } from "./actions/generate-trust-material.ts";
import { issueCredentialAction } from "./actions/issue.ts";
import { metadataAction } from "./actions/metadata.ts";
import { nonceAction } from "./actions/nonce.ts";
import { printResult } from "./io.ts";

export function createProgram(): Command {
	const program = new Command()
		.name("issuer-cli")
		.description("Demo issuer CLI for dc+sd-jwt issuance helpers");

	program
		.command("metadata")
		.description("Output issuer metadata")
		.option("--config <file>", "Read full issuer config JSON from file")
		.option(
			"--issuer <url>",
			"Override issuer identifier or build config inline",
		)
		.option(
			"--signing-key-file <file>",
			"Read signing key JSON or trust material JSON from file",
		)
		.option(
			"--credential-configuration-id <id>",
			"Credential configuration id for inline config",
		)
		.option("--vct <vct>", "Credential type for inline config")
		.option("--output <format>", "Output format: json|pretty", "pretty")
		.action(async (options) => {
			printResult(await metadataAction(options), options.output);
		});

	program
		.command("create-offer")
		.description("Create a pre-authorized credential offer")
		.option("--config <file>", "Read full issuer config JSON from file")
		.option(
			"--issuer <url>",
			"Override issuer identifier or build config inline",
		)
		.option(
			"--signing-key-file <file>",
			"Read signing key JSON or trust material JSON from file",
		)
		.option("--credential-configuration-id <id>", "Credential configuration id")
		.option("--vct <vct>", "Resolve credential configuration by vct")
		.option("--claims <json>", "Inline claim-set JSON")
		.option("--claims-file <file>", "Read claim-set JSON from file")
		.option("--expires-in <seconds>", "Grant lifetime override in seconds")
		.option("--output <format>", "Output format: json|pretty|raw", "pretty")
		.action(async (options) => {
			printResult(await createOfferAction(options), options.output);
		});

	program
		.command("create-grant")
		.description("Create a pre-authorized grant")
		.option("--config <file>", "Read full issuer config JSON from file")
		.option(
			"--issuer <url>",
			"Override issuer identifier or build config inline",
		)
		.option(
			"--signing-key-file <file>",
			"Read signing key JSON or trust material JSON from file",
		)
		.option("--credential-configuration-id <id>", "Credential configuration id")
		.option("--vct <vct>", "Resolve credential configuration by vct")
		.option("--claims <json>", "Inline claim-set JSON")
		.option("--claims-file <file>", "Read claim-set JSON from file")
		.option("--expires-in <seconds>", "Grant lifetime override in seconds")
		.option("--output <format>", "Output format: json|pretty|raw", "pretty")
		.action(async (options) => {
			printResult(await createGrantAction(options), options.output);
		});

	program
		.command("nonce")
		.description("Generate a proof nonce")
		.option("--config <file>", "Read full issuer config JSON from file")
		.option(
			"--issuer <url>",
			"Override issuer identifier or build config inline",
		)
		.option(
			"--signing-key-file <file>",
			"Read signing key JSON or trust material JSON from file",
		)
		.option(
			"--credential-configuration-id <id>",
			"Credential configuration id for inline config",
		)
		.option("--vct <vct>", "Credential type for inline config")
		.option("--output <format>", "Output format: json|pretty", "pretty")
		.action(async (options) => {
			printResult(await nonceAction(options), options.output);
		});

	program
		.command("issue")
		.description(
			"Issue a holder-bound dc+sd-jwt credential from claims and proof input",
		)
		.option("--config <file>", "Read full issuer config JSON from file")
		.option(
			"--issuer <url>",
			"Override issuer identifier or build config inline",
		)
		.option(
			"--signing-key-file <file>",
			"Read signing key JSON or trust material JSON from file",
		)
		.option("--credential-configuration-id <id>", "Credential configuration id")
		.option("--vct <vct>", "Resolve credential configuration by vct")
		.option(
			"--access-token <token>",
			"Use an already-derived access token in the current issuer instance",
		)
		.option(
			"--claims <json>",
			"Inline claim-set JSON for grant-derived issuance",
		)
		.option(
			"--claims-file <file>",
			"Read claim-set JSON from file for grant-derived issuance",
		)
		.option("--proof <value>", "Inline proof JWT or proof JSON")
		.option("--proof-file <file>", "Read proof JWT or proof JSON from file")
		.option("--output <format>", "Output format: json|pretty|raw", "pretty")
		.action(async (options) => {
			const result = await issueCredentialAction(options);
			if (options.output === "raw") {
				process.stdout.write(`${result.credential}\n`);
				return;
			}
			printResult(result, options.output);
		});

	program
		.command("generate-trust-material")
		.description(
			"Generate demo issuer key material, JWKS, and self-signed certificate artifacts",
		)
		.option("--kid <kid>", "Key id")
		.option(
			"--subject <subject>",
			"OpenSSL subject for self-signed certificate",
		)
		.option("--days-valid <days>", "Certificate validity in days")
		.option("--private-jwk-out <file>", "Write private JWK JSON")
		.option("--public-jwk-out <file>", "Write public JWK JSON")
		.option("--jwks-out <file>", "Write JWKS JSON")
		.option("--private-key-pem-out <file>", "Write private key PEM")
		.option("--public-key-pem-out <file>", "Write public key PEM")
		.option("--certificate-out <file>", "Write self-signed certificate PEM")
		.option(
			"--trust-artifact-out <file>",
			"Write verifier-facing trust artifact JSON",
		)
		.option("--output <format>", "Output format: json|pretty", "pretty")
		.action(async (options) => {
			printResult(await generateTrustMaterialAction(options), options.output);
		});

	return program;
}
