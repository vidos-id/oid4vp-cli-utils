import { verbose } from "@vidos-id/openid4vc-cli-common";
import {
	ACTIVE_TOKEN_STATUS,
	type CreateTemplateInput,
	createIssuanceInputSchema,
	createTemplateInputSchema,
	deleteResponseSchema,
	type Issuance,
	type IssuanceDetail,
	issuanceDetailSchema,
	REVOKED_TOKEN_STATUS,
	type SessionResponse,
	SUSPENDED_TOKEN_STATUS,
	sessionResponseSchema,
	type Template,
	templateSchema,
	type UpdateIssuanceStatusInput,
	updateIssuanceStatusInputSchema,
} from "@vidos-id/openid4vc-issuer-web-shared";
import type { StoredSession } from "./schemas.ts";
import {
	appErrorResponseSchema,
	authApiResponseSchema,
	issuanceListSchema,
	issuerMetadataSchema,
	templateListSchema,
} from "./schemas.ts";

type RequestOptions = Omit<RequestInit, "body"> & {
	body?: BodyInit | Record<string, unknown>;
};

export class IssuerWebClient {
	private cookieHeader = "";

	constructor(
		private readonly options: {
			serverUrl: string;
			fetchImpl?: typeof fetch;
			session?: StoredSession;
		},
	) {
		this.cookieHeader = options.session?.cookieHeader ?? "";
	}

	get serverUrl() {
		return this.options.serverUrl;
	}

	getCookieHeader() {
		return this.cookieHeader;
	}

	async signInAnonymous() {
		const response = await this.request("/api/auth/sign-in/anonymous", {
			method: "POST",
		});
		authApiResponseSchema.parse(
			await this.parseJson(response, "anonymous sign-in"),
		);
		return this.getSession();
	}

	async signInUsername(input: { username: string; password: string }) {
		const response = await this.request("/api/auth/sign-in/username", {
			method: "POST",
			body: input,
		});
		authApiResponseSchema.parse(
			await this.parseJson(response, "username sign-in"),
		);
		return this.getSession();
	}

	async signUpUsername(input: { username: string; password: string }) {
		const username = input.username.trim();
		const response = await this.request("/api/auth/sign-up/email", {
			method: "POST",
			body: {
				email: `temp-${crypto.randomUUID()}@issuer-web.local`,
				name: username,
				username,
				password: input.password,
			},
		});
		authApiResponseSchema.parse(await this.parseJson(response, "sign-up"));
		return this.getSession();
	}

	async signOut() {
		await this.request("/api/auth/sign-out", {
			method: "POST",
		});
		this.cookieHeader = "";
	}

	async getSession(): Promise<SessionResponse> {
		const response = await this.request("/api/session");
		const payload = sessionResponseSchema.parse(
			await this.parseJson(response, "session"),
		);
		return payload;
	}

	async getMetadata() {
		const response = await this.request(
			"/.well-known/openid-credential-issuer",
		);
		return issuerMetadataSchema.parse(
			await this.parseJson(response, "issuer metadata"),
		);
	}

	async listTemplates(): Promise<Template[]> {
		const response = await this.request("/api/templates");
		return templateListSchema.parse(
			await this.parseJson(response, "template list"),
		);
	}

	async createTemplate(input: CreateTemplateInput): Promise<Template> {
		const payload = createTemplateInputSchema.parse(input);
		const response = await this.request("/api/templates", {
			method: "POST",
			body: payload,
		});
		return templateSchema.parse(
			await this.parseJson(response, "template creation"),
		);
	}

	async deleteTemplate(templateId: string) {
		const response = await this.request(`/api/templates/${templateId}`, {
			method: "DELETE",
		});
		deleteResponseSchema.parse(
			await this.parseJson(response, "template deletion"),
		);
	}

	async listIssuances(): Promise<Issuance[]> {
		const response = await this.request("/api/issuances");
		return issuanceListSchema.parse(
			await this.parseJson(response, "issuance list"),
		);
	}

	async createIssuance(input: {
		templateId: string;
		claims?: Record<string, unknown>;
		status?: 0 | 1 | 2;
	}): Promise<IssuanceDetail> {
		const payload = createIssuanceInputSchema.parse(input);
		const response = await this.request("/api/issuances", {
			method: "POST",
			body: payload,
		});
		return issuanceDetailSchema.parse(
			await this.parseJson(response, "issuance creation"),
		);
	}

	async getIssuance(issuanceId: string): Promise<IssuanceDetail> {
		const response = await this.request(`/api/issuances/${issuanceId}`);
		return issuanceDetailSchema.parse(
			await this.parseJson(response, "issuance detail"),
		);
	}

	async updateIssuanceStatus(
		issuanceId: string,
		input: UpdateIssuanceStatusInput,
	): Promise<IssuanceDetail> {
		const payload = updateIssuanceStatusInputSchema.parse(input);
		const response = await this.request(`/api/issuances/${issuanceId}/status`, {
			method: "PATCH",
			body: payload,
		});
		return issuanceDetailSchema.parse(
			await this.parseJson(response, "issuance status update"),
		);
	}

	private async request(path: string, init: RequestOptions = {}) {
		const headers = new Headers(init.headers);
		headers.set("accept", "application/json");
		if (this.cookieHeader) {
			headers.set("cookie", this.cookieHeader);
		}

		let body = init.body;
		if (
			body &&
			typeof body === "object" &&
			!(body instanceof FormData) &&
			!(body instanceof URLSearchParams) &&
			!(body instanceof Blob) &&
			!(body instanceof ArrayBuffer)
		) {
			headers.set("content-type", "application/json");
			body = JSON.stringify(body);
		}

		const url = new URL(path, this.options.serverUrl);
		verbose(`Requesting ${init.method ?? "GET"} ${url}`);
		const response = await (this.options.fetchImpl ?? fetch)(url, {
			...init,
			headers,
			body: body as BodyInit | null | undefined,
		});
		this.updateCookies(response);
		if (!response.ok) {
			throw await this.createRequestError(response);
		}
		return response;
	}

	private updateCookies(response: Response) {
		const setCookies = getSetCookies(response.headers);
		if (setCookies.length === 0) {
			return;
		}
		this.cookieHeader = setCookies
			.map((value) => value.split(";")[0])
			.filter(Boolean)
			.join("; ");
	}

	private async createRequestError(response: Response) {
		let message = `Request failed with status ${response.status}`;
		try {
			const payload = appErrorResponseSchema.safeParse(await response.json());
			if (payload.success) {
				message = payload.data.message ?? payload.data.error ?? message;
			}
		} catch {
			try {
				const text = (await response.text()).trim();
				if (text) {
					message = text;
				}
			} catch {}
		}
		return new Error(message);
	}

	private async parseJson(response: Response, label: string) {
		try {
			return (await response.json()) as unknown;
		} catch {
			throw new Error(`Failed to parse ${label} response`);
		}
	}
}

export function statusLabelToValue(label: "active" | "revoked" | "suspended") {
	if (label === "active") return ACTIVE_TOKEN_STATUS;
	if (label === "revoked") return REVOKED_TOKEN_STATUS;
	return SUSPENDED_TOKEN_STATUS;
}

function getSetCookies(headers: Headers): string[] {
	const withGetSetCookie = headers as Headers & {
		getSetCookie?: () => string[];
	};
	if (typeof withGetSetCookie.getSetCookie === "function") {
		return withGetSetCookie.getSetCookie();
	}
	const combined = headers.get("set-cookie");
	if (!combined) {
		return [];
	}
	return combined.split(", ").filter((part) => part.includes("="));
}
