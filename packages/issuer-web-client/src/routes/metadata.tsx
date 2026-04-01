import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { PageShell, Section } from "../components/layout.tsx";
import { Button } from "../components/ui/button.tsx";
import { api } from "../lib/api.ts";

/** Subset of the OpenID4VCI issuer metadata response we render. */
interface IssuerMetadata {
	credential_issuer: string;
	token_endpoint: string;
	credential_endpoint: string;
	nonce_endpoint?: string;
	jwks: {
		keys: Array<Record<string, unknown>>;
	};
	credential_configurations_supported: Record<string, Record<string, unknown>>;
}

/** Convert a base64-encoded DER certificate (x5c entry) to PEM format. */
function x5cToPem(x5c: string): string {
	const lines: string[] = [];
	lines.push("-----BEGIN CERTIFICATE-----");
	for (let i = 0; i < x5c.length; i += 64) {
		lines.push(x5c.slice(i, i + 64));
	}
	lines.push("-----END CERTIFICATE-----");
	return lines.join("\n");
}

function CopyButton(props: { text: string }) {
	const [copied, setCopied] = useState(false);

	return (
		<Button
			variant="outline"
			size="sm"
			type="button"
			onClick={() => {
				void navigator.clipboard.writeText(props.text).then(() => {
					setCopied(true);
					setTimeout(() => setCopied(false), 2000);
				});
			}}
		>
			{copied ? (
				<>
					<Check className="mr-1.5 h-3.5 w-3.5" />
					Copied
				</>
			) : (
				<>
					<Copy className="mr-1.5 h-3.5 w-3.5" />
					Copy
				</>
			)}
		</Button>
	);
}

function CertificateBlock(props: { pem: string; index: number }) {
	return (
		<div className="space-y-2">
			<div className="flex items-center justify-between">
				<h4 className="text-sm font-medium">Certificate {props.index + 1}</h4>
				<CopyButton text={props.pem} />
			</div>
			<pre className="overflow-auto rounded-md border bg-muted p-4 font-mono text-xs leading-relaxed">
				{props.pem}
			</pre>
		</div>
	);
}

function JwkKeyCard(props: { jwk: Record<string, unknown>; keyIndex: number }) {
	const { jwk, keyIndex } = props;
	const x5cArray = Array.isArray(jwk.x5c) ? (jwk.x5c as string[]) : undefined;
	const pems = x5cArray?.map(x5cToPem);

	// Build a display copy of the JWK without x5c for readability (x5c is shown separately as PEM)
	const { x5c: _x5c, ...jwkWithoutX5c } = jwk;

	return (
		<div className="space-y-4 rounded-lg border p-5">
			<div className="flex items-center gap-3">
				<h3 className="text-sm font-semibold">
					Key {keyIndex + 1}
					{jwk.kid ? (
						<span className="ml-2 font-normal text-muted-foreground">
							kid: {String(jwk.kid)}
						</span>
					) : null}
				</h3>
				{jwk.alg ? (
					<span className="rounded-full border px-2.5 py-0.5 text-xs font-medium">
						{String(jwk.alg)}
					</span>
				) : null}
				{jwk.kty ? (
					<span className="rounded-full border px-2.5 py-0.5 text-xs font-medium text-muted-foreground">
						{String(jwk.kty)}
					</span>
				) : null}
			</div>

			{/* JWK properties (without x5c) */}
			<div className="space-y-2">
				<div className="flex items-center justify-between">
					<h4 className="text-sm font-medium">JWK (public key)</h4>
					<CopyButton text={JSON.stringify(jwk, null, 2)} />
				</div>
				<pre className="overflow-auto rounded-md border bg-muted p-4 font-mono text-xs">
					{JSON.stringify(jwkWithoutX5c, null, 2)}
				</pre>
			</div>

			{/* x5c certificates as PEM */}
			{pems && pems.length > 0 ? (
				<div className="space-y-4">
					<h4 className="text-sm font-semibold text-foreground">
						x5c Certificate Chain (PEM)
					</h4>
					{pems.map((pem, certIndex) => (
						<CertificateBlock
							key={pem.slice(0, 80)}
							pem={pem}
							index={certIndex}
						/>
					))}
				</div>
			) : (
				<p className="text-sm text-muted-foreground">
					No x5c certificate chain present on this key.
				</p>
			)}
		</div>
	);
}

function CredentialConfigCard(props: {
	configId: string;
	config: Record<string, unknown>;
}) {
	return (
		<div className="space-y-2 rounded-lg border p-4">
			<h4 className="text-sm font-semibold">{props.configId}</h4>
			<pre className="overflow-auto rounded-md border bg-muted p-4 font-mono text-xs">
				{JSON.stringify(props.config, null, 2)}
			</pre>
		</div>
	);
}

export function MetadataPage() {
	const [metadata, setMetadata] = useState<IssuerMetadata | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		void (async () => {
			try {
				const response = await api.getMetadata();
				if (!response.ok) {
					setError(`Failed to load metadata (${response.status})`);
					return;
				}
				const data = (await response.json()) as IssuerMetadata;
				setMetadata(data);
			} catch (err) {
				setError(
					err instanceof Error ? err.message : "Failed to load metadata",
				);
			} finally {
				setLoading(false);
			}
		})();
	}, []);

	const keys = metadata?.jwks?.keys ?? [];
	const credentialConfigs = metadata?.credential_configurations_supported ?? {};

	return (
		<PageShell
			title="Issuer Metadata"
			description="OpenID4VCI credential issuer metadata, including public signing keys and x5c certificate chain."
		>
			{loading ? (
				<p className="text-sm text-muted-foreground">Loading metadata...</p>
			) : error || !metadata ? (
				<p className="text-sm text-destructive">
					{error ?? "No metadata available"}
				</p>
			) : (
				<div className="space-y-10">
					{/* Endpoints */}
					<Section
						title="Endpoints"
						description="OpenID4VCI protocol endpoints advertised by this issuer."
					>
						<div className="overflow-hidden rounded-md border">
							<table className="w-full text-sm">
								<tbody className="divide-y">
									<EndpointRow
										label="Credential Issuer"
										value={metadata.credential_issuer}
									/>
									<EndpointRow
										label="Token Endpoint"
										value={metadata.token_endpoint}
									/>
									<EndpointRow
										label="Credential Endpoint"
										value={metadata.credential_endpoint}
									/>
									{metadata.nonce_endpoint ? (
										<EndpointRow
											label="Nonce Endpoint"
											value={metadata.nonce_endpoint}
										/>
									) : null}
								</tbody>
							</table>
						</div>
					</Section>

					{/* Signing Keys */}
					<Section
						title="Signing Keys"
						description="Issuer public keys from the JWKS. The x5c chain contains the issuer's public certificate in PEM format."
					>
						<div className="space-y-4">
							{keys.map((key, index) => (
								<JwkKeyCard
									key={typeof key.kid === "string" ? key.kid : `key-${index}`}
									jwk={key as Record<string, unknown>}
									keyIndex={index}
								/>
							))}
						</div>
					</Section>

					{/* Credential Configurations */}
					<Section
						title="Credential Configurations Supported"
						description="Credential types this issuer can issue."
					>
						<div className="space-y-4">
							{Object.entries(credentialConfigs).map(([configId, config]) => (
								<CredentialConfigCard
									key={configId}
									configId={configId}
									config={config as Record<string, unknown>}
								/>
							))}
						</div>
					</Section>

					{/* Raw JSON */}
					<Section
						title="Raw Metadata"
						description="Complete JSON response from /.well-known/openid-credential-issuer"
						actions={<CopyButton text={JSON.stringify(metadata, null, 2)} />}
					>
						<pre className="overflow-auto rounded-md border bg-muted p-4 font-mono text-xs">
							{JSON.stringify(metadata, null, 2)}
						</pre>
					</Section>
				</div>
			)}
		</PageShell>
	);
}

function EndpointRow(props: { label: string; value: string }) {
	return (
		<tr>
			<td className="whitespace-nowrap px-4 py-2.5 font-medium">
				{props.label}
			</td>
			<td className="break-all px-4 py-2.5 font-mono text-xs text-muted-foreground">
				{props.value}
			</td>
		</tr>
	);
}
