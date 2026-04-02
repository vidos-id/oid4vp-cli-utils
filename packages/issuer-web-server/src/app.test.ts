import { beforeEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { createAuthClient } from "better-auth/client";
import { anonymousClient, usernameClient } from "better-auth/client/plugins";
import { eq } from "drizzle-orm";
import {
	InMemoryWalletStorage,
	receiveCredentialFromOffer,
	Wallet,
} from "../../wallet/src/index.ts";
import { createServerApp } from "./app.ts";
import { readIssuerWebEnv } from "./config.ts";
import { createAppContext } from "./context.ts";
import { issuances, statusLists } from "./db/schema.ts";

const TEST_SECRET = "0123456789abcdef0123456789abcdef";

function createTestEnv(name: string) {
	return {
		ISSUER_WEB_DATABASE_PATH: `./.tmp/${name}.sqlite`,
		ISSUER_WEB_AUTH_SECRET: TEST_SECRET,
		ISSUER_WEB_ORIGIN: "http://localhost:3001",
		ISSUER_WEB_CLIENT_ORIGIN: "http://localhost:5174",
	};
}

async function exchangePreAuthorizedCode(
	fetchImpl: typeof fetch,
	preAuthorizedCode: string,
) {
	const formData = new FormData();
	formData.set(
		"grant_type",
		"urn:ietf:params:oauth:grant-type:pre-authorized_code",
	);
	formData.set("pre-authorized_code", preAuthorizedCode);
	const response = await fetchImpl("http://localhost:3001/token", {
		method: "POST",
		body: formData,
	});
	expect(response.status).toBe(200);
	return (await response.json()) as {
		access_token: string;
		c_nonce: string;
		credential_configuration_id: string;
		expires_in: number;
	};
}

function createCookieFetch(app: Awaited<ReturnType<typeof createServerApp>>) {
	let cookieHeader = "";
	return (async (input: RequestInfo | URL, init?: RequestInit) => {
		const headers = new Headers(init?.headers);
		if (cookieHeader) {
			headers.set("cookie", cookieHeader);
		}
		const request =
			input instanceof Request
				? new Request(input, { ...init, headers })
				: new Request(typeof input === "string" ? input : input.toString(), {
						...init,
						headers,
					});
		const response = await app.fetch(request);
		const setCookie = response.headers.get("set-cookie");
		if (setCookie) {
			cookieHeader = setCookie
				.split(", ")
				.map((part) => part.split(";")[0])
				.join("; ");
		}
		return response;
	}) as typeof fetch;
}

async function signUpAndCreateTemplate(fetchImpl: typeof fetch) {
	const auth = createAuthClient({
		baseURL: "http://localhost:3001/api/auth",
		plugins: [anonymousClient(), usernameClient()],
		fetchOptions: {
			customFetchImpl: fetchImpl,
		},
	});

	const signUpResult = await auth.signUp.email({
		email: "ada@example.com",
		password: "very-secure-password",
		name: "ada",
		username: "ada",
	});
	expect(signUpResult.error).toBeNull();

	const templateResponse = await fetchImpl(
		"http://localhost:3001/api/templates",
		{
			method: "POST",
			headers: {
				"content-type": "application/json",
			},
			body: JSON.stringify({
				name: "Conference Pass",
				vct: "urn:eudi:pid:1",
				defaultClaims: {
					given_name: "Ada",
					family_name: "Lovelace",
					pass_level: "speaker",
				},
			}),
		},
	);
	expect(templateResponse.status).toBe(200);
	return (await templateResponse.json()) as {
		id: string;
		credentialConfigurationId: string;
	};
}

describe("issuer web server", () => {
	beforeEach(async () => {
		await Bun.write("./.tmp/.gitkeep", "");
		await rm("./.tmp/issuer-web-e2e.sqlite", { force: true });
		await rm("./.tmp/issuer-web-link-anonymous.sqlite", { force: true });
		await rm("./.tmp/issuer-web-ownership.sqlite", { force: true });
		await rm("./.tmp/issuer-web-redeem-twice.sqlite", { force: true });
		await rm("./.tmp/issuer-web-custom-grant-ttl.sqlite", { force: true });
		await rm("./.tmp/issuer-web-legacy-state.sqlite", { force: true });
		await rm("./.tmp/issuer-web-status-source-of-truth.sqlite", {
			force: true,
		});
		await rm("./.tmp/issuer-web-stable-status-list-jwt.sqlite", {
			force: true,
		});
		await rm("./.tmp/issuer-web-multi-origin.sqlite", { force: true });
		await rm("./.tmp/issuer-web-predefined-templates.sqlite", {
			force: true,
		});
		await rm("./.tmp/issuer-web-predefined-issuance.sqlite", {
			force: true,
		});
	});

	test("supports signup, template creation, issuance, wallet receipt, and status updates", async () => {
		const context = await createAppContext(createTestEnv("issuer-web-e2e"));
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
					claims: {
						seat: "A-12",
					},
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const issuanceDetail = (await issuanceResponse.json()) as {
			issuance: { id: string; offerUri: string; state: string };
		};
		expect(issuanceDetail.issuance.offerUri).toContain(
			"openid-credential-offer://",
		);
		expect(issuanceDetail.issuance.state).toBe("offered");
		const storedIssuance = await context.db.query.issuances.findFirst();
		expect(storedIssuance?.preAuthorizedCode).toBeTruthy();

		const wallet = new Wallet(new InMemoryWalletStorage());
		const stored = await receiveCredentialFromOffer(
			wallet,
			issuanceDetail.issuance.offerUri,
			{
				fetch: fetchImpl,
			},
		);
		expect(stored.vct).toBe("urn:eudi:pid:1");
		const redeemedIssuance = await context.db.query.issuances.findFirst();
		expect(redeemedIssuance?.state).toBe("redeemed");
		const activeStatus = await wallet.getCredentialStatus(stored.id, {
			fetch: fetchImpl,
		});
		expect(activeStatus?.status.value).toBe(0);

		const suspendResponse = await fetchImpl(
			`http://localhost:3001/api/issuances/${issuanceDetail.issuance.id}/status`,
			{
				method: "PATCH",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({ status: 2 }),
			},
		);
		expect(suspendResponse.status).toBe(200);
		const suspendedStatus = await wallet.getCredentialStatus(stored.id, {
			fetch: fetchImpl,
		});
		expect(suspendedStatus?.status.value).toBe(2);

		const revokeResponse = await fetchImpl(
			`http://localhost:3001/api/issuances/${issuanceDetail.issuance.id}/status`,
			{
				method: "PATCH",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({ status: 1 }),
			},
		);
		expect(revokeResponse.status).toBe(200);
		const revokedStatus = await wallet.getCredentialStatus(stored.id, {
			fetch: fetchImpl,
		});
		expect(revokedStatus?.status.value).toBe(1);
	});

	test("returns predefined templates without storing them in the database", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-predefined-templates"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const auth = createAuthClient({
			baseURL: "http://localhost:3001/api/auth",
			plugins: [anonymousClient(), usernameClient()],
			fetchOptions: {
				customFetchImpl: fetchImpl,
			},
		});

		const signUpResult = await auth.signUp.email({
			email: "predefined@example.com",
			password: "very-secure-password",
			name: "predefined",
			username: "predefined",
		});
		expect(signUpResult.error).toBeNull();

		const templatesResponse = await fetchImpl(
			"http://localhost:3001/api/templates",
		);
		expect(templatesResponse.status).toBe(200);
		const templates = (await templatesResponse.json()) as Array<{
			id: string;
			kind: string;
			credentialConfigurationId: string;
		}>;
		expect(
			templates.some(
				(template) =>
					template.id === "predefined:eudi-pid-sd-jwt" &&
					template.kind === "predefined" &&
					template.credentialConfigurationId === "urn:eudi:pid:1",
			),
		).toBe(true);

		const storedTemplates =
			await context.db.query.credentialTemplates.findMany();
		expect(storedTemplates).toHaveLength(0);
	});

	test("supports issuing from a predefined template", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-predefined-issuance"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const auth = createAuthClient({
			baseURL: "http://localhost:3001/api/auth",
			plugins: [anonymousClient(), usernameClient()],
			fetchOptions: {
				customFetchImpl: fetchImpl,
			},
		});

		const signUpResult = await auth.signUp.email({
			email: "predefined-issuance@example.com",
			password: "very-secure-password",
			name: "predefinedissuance",
			username: "predefinedissuance",
		});
		expect(signUpResult.error).toBeNull();

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: "predefined:eudi-pid-sd-jwt",
					claims: {
						seat: "B-15",
					},
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const detail = (await issuanceResponse.json()) as {
			issuance: { templateId: string; credentialConfigurationId: string };
		};
		expect(detail.issuance.templateId).toBe("predefined:eudi-pid-sd-jwt");
		expect(detail.issuance.credentialConfigurationId).toBe("urn:eudi:pid:1");
	});

	test("returns a stable status list JWT until the list changes", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-stable-status-list-jwt"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const created = (await issuanceResponse.json()) as {
			issuance: { id: string; statusListId: string };
		};

		const firstResponse = await fetchImpl(
			`http://localhost:3001/status-lists/${created.issuance.statusListId}`,
		);
		expect(firstResponse.status).toBe(200);
		const firstJwt = await firstResponse.text();

		const secondResponse = await fetchImpl(
			`http://localhost:3001/status-lists/${created.issuance.statusListId}`,
		);
		expect(secondResponse.status).toBe(200);
		const secondJwt = await secondResponse.text();
		expect(secondJwt).toBe(firstJwt);

		const updateResponse = await fetchImpl(
			`http://localhost:3001/api/issuances/${created.issuance.id}/status`,
			{
				method: "PATCH",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({ status: 2 }),
			},
		);
		expect(updateResponse.status).toBe(200);

		const updatedResponse = await fetchImpl(
			`http://localhost:3001/status-lists/${created.issuance.statusListId}`,
		);
		expect(updatedResponse.status).toBe(200);
		const updatedJwt = await updatedResponse.text();
		expect(updatedJwt).not.toBe(firstJwt);
	});

	test("reuses an active access token when the same offer is redeemed twice", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-redeem-twice"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const storedIssuance = await context.db.query.issuances.findFirst();
		expect(storedIssuance?.preAuthorizedCode).toBeTruthy();
		if (!storedIssuance?.preAuthorizedCode) {
			throw new Error("Expected issuance with a pre-authorized code");
		}

		const first = await exchangePreAuthorizedCode(
			fetchImpl,
			storedIssuance.preAuthorizedCode,
		);
		const second = await exchangePreAuthorizedCode(
			fetchImpl,
			storedIssuance.preAuthorizedCode,
		);

		expect(second.access_token).toBe(first.access_token);
		expect(second.c_nonce).not.toBe(first.c_nonce);
		const redeemingIssuance = await context.db.query.issuances.findFirst();
		expect(redeemingIssuance?.state).toBe("redeeming");
		const allAccessTokens = await context.db.query.accessTokens.findMany();
		expect(allAccessTokens).toHaveLength(1);
		const allNonces = await context.db.query.nonces.findMany();
		expect(allNonces.filter((nonce) => nonce.used === false)).toHaveLength(1);
	});

	test("uses the configured pre-authorized code ttl for new offers", async () => {
		const context = await createAppContext({
			...createTestEnv("issuer-web-custom-grant-ttl"),
			ISSUER_WEB_PRE_AUTHORIZED_CODE_TTL_SECONDS: "7200",
		});
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);

		const grant = await context.db.query.preAuthorizedGrants.findFirst();
		expect(grant).toBeTruthy();
		if (!grant) {
			throw new Error("Expected a stored pre-authorized grant");
		}
		const ttlSeconds = Math.round(
			(grant.expiresAt.getTime() - Date.now()) / 1000,
		);
		expect(ttlSeconds).toBeGreaterThan(7190);
		expect(ttlSeconds).toBeLessThanOrEqual(7200);
	});

	test("maps legacy issued state rows into redeemed responses", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-legacy-state"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const created = (await issuanceResponse.json()) as {
			issuance: { id: string };
		};

		await context.db
			.update(issuances)
			.set({ state: "issued" })
			.where(eq(issuances.id, created.issuance.id));

		const listResponse = await fetchImpl("http://localhost:3001/api/issuances");
		expect(listResponse.status).toBe(200);
		const listed = (await listResponse.json()) as Array<{ state: string }>;
		expect(listed[0]?.state).toBe("redeemed");

		const detailResponse = await fetchImpl(
			`http://localhost:3001/api/issuances/${created.issuance.id}`,
		);
		expect(detailResponse.status).toBe(200);
		const detail = (await detailResponse.json()) as {
			issuance: { state: string };
		};
		expect(detail.issuance.state).toBe("redeemed");
	});

	test("reads issuance status from the status list rather than issuance fields", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-status-source-of-truth"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const template = await signUpAndCreateTemplate(fetchImpl);

		const issuanceResponse = await fetchImpl(
			"http://localhost:3001/api/issuances",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					templateId: template.id,
				}),
			},
		);
		expect(issuanceResponse.status).toBe(200);
		const created = (await issuanceResponse.json()) as {
			issuance: { id: string; statusListId: string; statusListIndex: number };
		};

		const statusListRow = await context.db.query.statusLists.findFirst({
			where: eq(statusLists.id, created.issuance.statusListId),
		});
		if (!statusListRow) {
			throw new Error("Expected stored status list row");
		}
		const statuses = JSON.parse(statusListRow.statusesJson) as number[];
		statuses[created.issuance.statusListIndex] = 2;

		await context.db
			.update(statusLists)
			.set({ statusesJson: JSON.stringify(statuses) })
			.where(eq(statusLists.id, created.issuance.statusListId));

		const detailResponse = await fetchImpl(
			`http://localhost:3001/api/issuances/${created.issuance.id}`,
		);
		expect(detailResponse.status).toBe(200);
		const detail = (await detailResponse.json()) as {
			issuance: { status: number };
		};
		expect(detail.issuance.status).toBe(2);
	});

	test("accepts multiple trusted client origins from env", async () => {
		const env = readIssuerWebEnv({
			...createTestEnv("issuer-web-multi-origin"),
			ISSUER_WEB_CLIENT_ORIGINS:
				"https://barely-certain-mammoth.ngrok-free.app, https://second.example",
		});

		expect(env.ISSUER_WEB_CLIENT_ORIGINS).toEqual([
			"https://barely-certain-mammoth.ngrok-free.app",
			"https://second.example",
		]);
	});

	test("restricts templates and issuances to the owning user", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-ownership"),
		);
		const app = await createServerApp(context);
		const ownerFetch = createCookieFetch(app);
		const ownerTemplate = await signUpAndCreateTemplate(ownerFetch);
		const secondFetch = createCookieFetch(app);

		const auth2 = createAuthClient({
			baseURL: "http://localhost:3001/api/auth",
			plugins: [anonymousClient(), usernameClient()],
			fetchOptions: {
				customFetchImpl: secondFetch,
			},
		});
		await auth2.signUp.email({
			email: "grace@example.com",
			password: "very-secure-password",
			name: "grace",
			username: "grace",
		});

		const templatesResponse = await secondFetch(
			"http://localhost:3001/api/templates",
		);
		expect(templatesResponse.status).toBe(200);
		const templates = (await templatesResponse.json()) as Array<{ id: string }>;
		expect(templates.some((template) => template.id === ownerTemplate.id)).toBe(
			false,
		);

		const forbiddenPatch = await secondFetch(
			`http://localhost:3001/api/templates/${ownerTemplate.id}`,
			{
				method: "PATCH",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({ name: "Intruder Edit" }),
			},
		);
		expect(forbiddenPatch.status).toBe(403);
	});

	test("links anonymous users to username accounts without losing owned data", async () => {
		const context = await createAppContext(
			createTestEnv("issuer-web-link-anonymous"),
		);
		const app = await createServerApp(context);
		const fetchImpl = createCookieFetch(app);
		const auth = createAuthClient({
			baseURL: "http://localhost:3001/api/auth",
			plugins: [anonymousClient(), usernameClient()],
			fetchOptions: {
				customFetchImpl: fetchImpl,
			},
		});

		const anonymousSignIn = await (
			auth.signIn as unknown as {
				anonymous: () => Promise<{ error: { message?: string } | null }>;
			}
		).anonymous();
		expect(anonymousSignIn.error).toBeNull();

		const sessionBeforeLink = await auth.getSession();
		expect(sessionBeforeLink.data?.user).toBeTruthy();
		expect(sessionBeforeLink.data?.user.isAnonymous).toBe(true);

		const templateResponse = await fetchImpl(
			"http://localhost:3001/api/templates",
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
				},
				body: JSON.stringify({
					name: "Guest Template",
					vct: "urn:eudi:pid:1",
					defaultClaims: {
						given_name: "Guest",
					},
				}),
			},
		);
		expect(templateResponse.status).toBe(200);
		const template = (await templateResponse.json()) as { id: string };

		const linkResult = await auth.signUp.email({
			email: `temp-${crypto.randomUUID()}@issuer-web.local`,
			password: "very-secure-password",
			name: "linkeduser",
			username: "linkeduser",
		});
		expect(linkResult.error).toBeNull();

		const sessionAfterLink = await auth.getSession();
		expect(sessionAfterLink.data?.user.isAnonymous).toBe(false);
		expect(sessionAfterLink.data?.user.username).toBe("linkeduser");

		const templatesResponse = await fetchImpl(
			"http://localhost:3001/api/templates",
		);
		expect(templatesResponse.status).toBe(200);
		const templates = (await templatesResponse.json()) as Array<{ id: string }>;
		expect(templates.some((item) => item.id === template.id)).toBe(true);
	});
});
