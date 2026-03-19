export class IssuerError extends Error {
	constructor(
		readonly code:
			| "invalid_request"
			| "invalid_grant"
			| "invalid_token"
			| "invalid_proof"
			| "unsupported_credential_configuration"
			| "unsupported_tx_code",
		message: string,
	) {
		super(message);
		this.name = "IssuerError";
	}
}
