import type {
	CreateTemplateInput,
	Template,
	UpdateTemplateInput,
} from "@vidos-id/issuer-web-shared";
import {
	createTemplateInputSchema,
	templateSchema,
	updateTemplateInputSchema,
} from "@vidos-id/issuer-web-shared";
import { and, eq } from "drizzle-orm";
import type { IssuerWebDatabase } from "../db/index.ts";
import { credentialTemplates } from "../db/schema.ts";
import { forbidden, notFound } from "../errors.ts";
import { asIsoString, jsonParse, now } from "../utils.ts";
import {
	getPredefinedTemplateById,
	PREDEFINED_TEMPLATES,
} from "./predefined-templates.ts";

function toTemplate(row: typeof credentialTemplates.$inferSelect): Template {
	return templateSchema.parse({
		id: row.id,
		ownerUserId: row.ownerUserId,
		name: row.name,
		kind: row.kind,
		credentialConfigurationId: row.credentialConfigurationId,
		vct: row.vct,
		defaultClaims: jsonParse(row.defaultClaimsJson),
		createdAt: asIsoString(row.createdAt),
		updatedAt: asIsoString(row.updatedAt),
	});
}

function createConfigurationId(name: string) {
	const slug = name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	return `custom-${slug}-${crypto.randomUUID().slice(0, 8)}`;
}

export class TemplateService {
	constructor(private readonly db: IssuerWebDatabase) {}

	async listForUser(userId: string) {
		const rows = await this.db.query.credentialTemplates.findMany({
			where: and(
				eq(credentialTemplates.isActive, true),
				eq(credentialTemplates.kind, "custom"),
				eq(credentialTemplates.ownerUserId, userId),
			),
		});
		return [...PREDEFINED_TEMPLATES, ...rows.map(toTemplate)];
	}

	async listActive() {
		const rows = await this.db.query.credentialTemplates.findMany({
			where: and(
				eq(credentialTemplates.isActive, true),
				eq(credentialTemplates.kind, "custom"),
			),
		});
		return [...PREDEFINED_TEMPLATES, ...rows.map(toTemplate)];
	}

	async create(userId: string, input: CreateTemplateInput) {
		const parsed = createTemplateInputSchema.parse(input);
		const createdAt = now();
		const row = {
			id: crypto.randomUUID(),
			ownerUserId: userId,
			name: parsed.name,
			kind: "custom",
			credentialConfigurationId: createConfigurationId(parsed.name),
			vct: parsed.vct,
			defaultClaimsJson: JSON.stringify(parsed.defaultClaims),
			isActive: true,
			createdAt,
			updatedAt: createdAt,
		} satisfies typeof credentialTemplates.$inferInsert;
		await this.db.insert(credentialTemplates).values(row);
		return toTemplate(row as typeof credentialTemplates.$inferSelect);
	}

	async update(userId: string, templateId: string, input: UpdateTemplateInput) {
		const parsed = updateTemplateInputSchema.parse(input);
		const row = await this.db.query.credentialTemplates.findFirst({
			where: eq(credentialTemplates.id, templateId),
		});
		if (!row) {
			throw notFound("Template not found");
		}
		if (row.ownerUserId !== userId) {
			throw forbidden();
		}
		const updatedAt = now();
		await this.db
			.update(credentialTemplates)
			.set({
				name: parsed.name ?? row.name,
				vct: parsed.vct ?? row.vct,
				defaultClaimsJson: parsed.defaultClaims
					? JSON.stringify(parsed.defaultClaims)
					: row.defaultClaimsJson,
				updatedAt,
			})
			.where(eq(credentialTemplates.id, row.id));
		return this.getOwnedById(userId, templateId);
	}

	async getOwnedById(userId: string, templateId: string) {
		const row = await this.db.query.credentialTemplates.findFirst({
			where: eq(credentialTemplates.id, templateId),
		});
		if (!row) {
			throw notFound("Template not found");
		}
		if (row.ownerUserId !== userId) {
			throw forbidden();
		}
		return toTemplate(row);
	}

	async getAccessibleById(userId: string, templateId: string) {
		const predefinedTemplate = getPredefinedTemplateById(templateId);
		if (predefinedTemplate) {
			return predefinedTemplate;
		}

		const row = await this.db.query.credentialTemplates.findFirst({
			where: eq(credentialTemplates.id, templateId),
		});
		if (!row) {
			throw notFound("Template not found");
		}
		if (row.ownerUserId !== userId) {
			throw forbidden();
		}
		return toTemplate(row);
	}

	async delete(userId: string, templateId: string) {
		const row = await this.db.query.credentialTemplates.findFirst({
			where: eq(credentialTemplates.id, templateId),
		});
		if (!row) {
			throw notFound("Template not found");
		}
		if (row.ownerUserId !== userId) {
			throw forbidden();
		}
		await this.db
			.delete(credentialTemplates)
			.where(eq(credentialTemplates.id, templateId));
	}

	async getActiveByConfigurationId(credentialConfigurationId: string) {
		const row = await this.db.query.credentialTemplates.findFirst({
			where: and(
				eq(
					credentialTemplates.credentialConfigurationId,
					credentialConfigurationId,
				),
				eq(credentialTemplates.isActive, true),
			),
		});
		if (!row) {
			throw notFound("Template not found for credential configuration");
		}
		return toTemplate(row);
	}
}
