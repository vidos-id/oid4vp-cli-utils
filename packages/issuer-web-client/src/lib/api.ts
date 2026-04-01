import { env } from "../env.ts";

async function request<T>(path: string, init?: RequestInit) {
	const response = await fetch(new URL(path, env.VITE_ISSUER_WEB_SERVER_URL), {
		...init,
		credentials: "include",
		headers: {
			accept: "application/json",
			...(init?.headers ?? {}),
		},
	});
	return response as Response & { json(): Promise<T> };
}

export const api = {
	getMetadata: () => request("/.well-known/openid-credential-issuer"),
	listTemplates: () => request("/api/templates"),
	createTemplate: (json: unknown) =>
		request("/api/templates", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(json),
		}),
	deleteTemplate: (id: string) =>
		request(`/api/templates/${id}`, {
			method: "DELETE",
		}),
	listIssuances: () => request("/api/issuances"),
	createIssuance: (json: unknown) =>
		request("/api/issuances", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(json),
		}),
	getIssuance: (id: string) => request(`/api/issuances/${id}`),
	updateIssuanceStatus: (id: string, json: unknown) =>
		request(`/api/issuances/${id}/status`, {
			method: "PATCH",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(json),
		}),
};
