import { relations } from "drizzle-orm";
import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("user", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	email: text("email").notNull().unique(),
	username: text("username").unique(),
	displayUsername: text("display_username"),
	isAnonymous: integer("is_anonymous", { mode: "boolean" })
		.notNull()
		.default(false),
	emailVerified: integer("email_verified", { mode: "boolean" })
		.notNull()
		.default(false),
	image: text("image"),
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

export const sessions = sqliteTable(
	"session",
	{
		id: text("id").primaryKey(),
		expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
		token: text("token").notNull().unique(),
		createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
		ipAddress: text("ip_address"),
		userAgent: text("user_agent"),
		userId: text("user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
	},
	(table) => [index("idx_session_user_id").on(table.userId)],
);

export const accounts = sqliteTable(
	"account",
	{
		id: text("id").primaryKey(),
		accountId: text("account_id").notNull(),
		providerId: text("provider_id").notNull(),
		userId: text("user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		accessToken: text("access_token"),
		refreshToken: text("refresh_token"),
		idToken: text("id_token"),
		accessTokenExpiresAt: integer("access_token_expires_at", {
			mode: "timestamp_ms",
		}),
		refreshTokenExpiresAt: integer("refresh_token_expires_at", {
			mode: "timestamp_ms",
		}),
		scope: text("scope"),
		password: text("password"),
		createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
	},
	(table) => [index("idx_account_user_id").on(table.userId)],
);

export const verifications = sqliteTable(
	"verification",
	{
		id: text("id").primaryKey(),
		identifier: text("identifier").notNull(),
		value: text("value").notNull(),
		expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
		createdAt: integer("created_at", { mode: "timestamp_ms" }),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" }),
	},
	(table) => [index("idx_verification_identifier").on(table.identifier)],
);

export const issuerConfig = sqliteTable("issuer_config", {
	id: text("id").primaryKey(),
	issuerUrl: text("issuer_url").notNull(),
	name: text("name").notNull(),
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

export const issuerSigningKeys = sqliteTable("issuer_signing_key", {
	id: text("id").primaryKey(),
	alg: text("alg").notNull(),
	privateJwkJson: text("private_jwk_json").notNull(),
	publicJwkJson: text("public_jwk_json").notNull(),
	isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

export const credentialTemplates = sqliteTable(
	"credential_template",
	{
		id: text("id").primaryKey(),
		ownerUserId: text("owner_user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		name: text("name").notNull(),
		kind: text("kind").notNull(),
		credentialConfigurationId: text("credential_configuration_id")
			.notNull()
			.unique(),
		vct: text("vct").notNull(),
		defaultClaimsJson: text("default_claims_json").notNull(),
		isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
		createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
	},
	(table) => [index("idx_template_owner").on(table.ownerUserId)],
);

export const statusLists = sqliteTable("status_list", {
	id: text("id").primaryKey(),
	uri: text("uri").notNull().unique(),
	bits: integer("bits").notNull(),
	statusesJson: text("statuses_json").notNull(),
	statusListJwt: text("status_list_jwt").notNull(),
	ttl: integer("ttl"),
	expiresAt: integer("expires_at", { mode: "timestamp_ms" }),
	isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
	createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

export const issuances = sqliteTable(
	"issuance",
	{
		id: text("id").primaryKey(),
		ownerUserId: text("owner_user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		templateId: text("template_id").notNull(),
		credentialConfigurationId: text("credential_configuration_id").notNull(),
		vct: text("vct").notNull(),
		claimsJson: text("claims_json").notNull(),
		state: text("state").notNull(),
		offerUri: text("offer_uri").notNull(),
		preAuthorizedCode: text("pre_authorized_code").notNull().unique(),
		accessToken: text("access_token").unique(),
		credential: text("credential"),
		statusListId: text("status_list_id")
			.notNull()
			.references(() => statusLists.id, { onDelete: "cascade" }),
		statusListIndex: integer("status_list_index").notNull(),
		createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
		updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
	},
	(table) => [
		index("idx_issuance_owner").on(table.ownerUserId),
		index("idx_issuance_template").on(table.templateId),
	],
);

export const preAuthorizedGrants = sqliteTable("pre_authorized_grant", {
	id: text("id").primaryKey(),
	issuanceId: text("issuance_id")
		.notNull()
		.references(() => issuances.id, { onDelete: "cascade" }),
	preAuthorizedCode: text("pre_authorized_code").notNull().unique(),
	credentialConfigurationId: text("credential_configuration_id").notNull(),
	claimsJson: text("claims_json").notNull(),
	expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
	used: integer("used", { mode: "boolean" }).notNull().default(false),
});

export const accessTokens = sqliteTable("access_token", {
	id: text("id").primaryKey(),
	issuanceId: text("issuance_id")
		.notNull()
		.references(() => issuances.id, { onDelete: "cascade" }),
	accessToken: text("access_token").notNull().unique(),
	credentialConfigurationId: text("credential_configuration_id").notNull(),
	claimsJson: text("claims_json").notNull(),
	expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
	used: integer("used", { mode: "boolean" }).notNull().default(false),
});

export const nonces = sqliteTable("nonce", {
	id: text("id").primaryKey(),
	issuanceId: text("issuance_id")
		.notNull()
		.references(() => issuances.id, { onDelete: "cascade" }),
	cNonce: text("c_nonce").notNull().unique(),
	expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
	used: integer("used", { mode: "boolean" }).notNull().default(false),
});

export const userRelations = relations(users, ({ many }) => ({
	templates: many(credentialTemplates),
	issuances: many(issuances),
}));

export const user = users;
export const session = sessions;
export const account = accounts;
export const verification = verifications;
