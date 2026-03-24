import { printResult, setVerbose, verbose } from "cli-common";
import { Command } from "commander";
import { generateTrustMaterialAction } from "./actions/generate-trust-material.ts";
import { importTrustMaterialAction } from "./actions/import-trust-material.ts";
import { initIssuerAction } from "./actions/init.ts";
import { issueCredentialAction } from "./actions/issue.ts";

export function createProgram(version: string): Command {
	const program = new Command()
		.name("issuer-cli")
		.version(version)
		.description("Demo issuer CLI for dc+sd-jwt credential issuance")
		.option("--verbose", "Enable verbose logging to stderr", false)
		.hook("preAction", (_thisCommand, actionCommand) => {
			const opts = actionCommand.optsWithGlobals();
			if (opts.verbose) {
				setVerbose(true);
			}
		});

	program
		.command("init")
		.description(
			"Initialize an issuer directory with signing keys, JWKS, and trust material",
		)
		.requiredOption(
			"--issuer-dir <dir>",
			"Path to the issuer directory (created if it does not exist)",
		)
		.addHelpText(
			"after",
			`
Examples:
  $ issuer-cli init --issuer-dir ./my-issuer`,
		)
		.action(async (options) => {
			verbose(`Initializing issuer in ${options.issuerDir}`);
			printResult(await initIssuerAction(options), "json");
		});

	program
		.command("issue")
		.description(
			"Issue a dc+sd-jwt credential and write it to the issuer directory",
		)
		.requiredOption(
			"--issuer-dir <dir>",
			"Path to the issuer directory containing signing-key.json",
		)
		.requiredOption(
			"--issuer <url>",
			"Issuer identifier URL (e.g. https://issuer.example)",
		)
		.requiredOption(
			"--vct <uri>",
			"Verifiable Credential Type URI (e.g. urn:eudi:pid:1)",
		)
		.option(
			"--claims <json>",
			'Inline JSON object with credential claims (e.g. \'{"given_name":"Ada"}\')',
		)
		.option(
			"--claims-file <file>",
			"Path to a JSON file containing credential claims",
		)
		.option(
			"--holder-key-file <file>",
			"Path to the wallet holder-key.json for holder binding (omit for unbound credentials)",
		)
		.option(
			"--holder-key <json>",
			"Inline holder key JWK JSON for holder binding (alternative to --holder-key-file)",
		)
		.option(
			"--credential-file <name>",
			"Output credential filename within --issuer-dir (default: credential-<uuid>.txt)",
		)
		.option(
			"--signing-key-file <file>",
			"Path to a signing key JSON file (overrides the one in --issuer-dir)",
		)
		.option(
			"--output <format>",
			"Output format: json or raw (compact credential text only)",
			"json",
		)
		.addHelpText(
			"after",
			`
Examples:
  Issue an unbound credential:
    $ issuer-cli issue \
        --issuer-dir ./my-issuer \
        --issuer https://issuer.example \
        --vct urn:eudi:pid:1 \
        --claims-file claims.json

  Issue a holder-bound credential:
    $ issuer-cli issue \
        --issuer-dir ./my-issuer \
        --issuer https://issuer.example \
        --vct urn:eudi:pid:1 \
        --claims-file claims.json \
        --holder-key-file ./wallet/holder-key.json

  Issue a holder-bound credential with inline holder key:
    $ issuer-cli issue \
        --issuer-dir ./my-issuer \
        --issuer https://issuer.example \
        --vct urn:eudi:pid:1 \
        --claims-file claims.json \
        --holder-key '{"kty":"EC","crv":"P-256",...}'`,
		)
		.action(async (options) => {
			verbose(`Issuing credential to ${options.issuerDir}`);
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
		.option(
			"--issuer-dir <dir>",
			"Write default output files (signing-key.json, jwks.json, trust.json) to this directory",
		)
		.option(
			"--kid <kid>",
			"Key id for the generated key pair (default: issuer-key-1)",
		)
		.option(
			"--alg <algorithm>",
			"Signing algorithm: ES256, ES384, or EdDSA (default: EdDSA)",
		)
		.option(
			"--subject <subject>",
			"OpenSSL subject for the self-signed certificate (default: /CN=Demo Issuer/O=oid4vp-cli-utils)",
		)
		.option(
			"--days-valid <days>",
			"Certificate validity in days (default: 365)",
		)
		.addHelpText(
			"after",
			`
Examples:
  $ issuer-cli generate-trust-material --issuer-dir ./my-issuer`,
		)
		.action(async (options) => {
			verbose("Generating trust material");
			printResult(await generateTrustMaterialAction(options), "json");
		});

	program
		.command("import-trust-material")
		.description(
			"Import existing key material and produce issuer signing-key, JWKS, and trust artifacts",
		)
		.requiredOption(
			"--issuer-dir <dir>",
			"Output directory for signing-key.json, jwks.json, and trust.json",
		)
		.requiredOption(
			"--private-key <file>",
			"Path to private key file (JWK JSON or PKCS#8 PEM, auto-detected)",
		)
		.option(
			"--certificate <file>",
			"Path to PEM certificate file (if omitted, a self-signed certificate is generated)",
		)
		.option(
			"--alg <algorithm>",
			"Signing algorithm: ES256, ES384, or EdDSA (inferred from key if omitted)",
		)
		.addHelpText(
			"after",
			`
Examples:
  Import a PEM private key (generates self-signed certificate):
    $ issuer-cli import-trust-material \\
        --issuer-dir ./my-issuer \\
        --private-key ./private-key.pem

  Import a JWK private key with existing certificate:
    $ issuer-cli import-trust-material \\
        --issuer-dir ./my-issuer \\
        --private-key ./private-key.json \\
        --certificate ./cert.pem

  Import with explicit algorithm:
    $ issuer-cli import-trust-material \\
        --issuer-dir ./my-issuer \\
        --private-key ./key.pem \\
        --alg ES256`,
		)
		.action(async (options) => {
			verbose("Importing trust material");
			printResult(await importTrustMaterialAction(options), "json");
		});

	return program;
}
