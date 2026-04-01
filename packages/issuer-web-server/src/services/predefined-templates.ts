import type { Template } from "@vidos-id/issuer-web-shared";
import { templateSchema } from "@vidos-id/issuer-web-shared";

const PREDEFINED_TEMPLATE_OWNER_ID = "system-user";
const PREDEFINED_TEMPLATE_TIMESTAMP = "2026-01-01T00:00:00.000Z";

export const PREDEFINED_TEMPLATES = [
	templateSchema.parse({
		id: "predefined:eudi-pid-sd-jwt",
		ownerUserId: PREDEFINED_TEMPLATE_OWNER_ID,
		name: "EUDI PID (SD-JWT)",
		kind: "predefined",
		credentialConfigurationId: "urn:eudi:pid:1",
		vct: "urn:eudi:pid:1",
		defaultClaims: {
			family_name: "Lovelace",
			given_name: "Ada",
			birthdate: "1815-12-10",
			age_over_18: true,
			family_name_birth: "Byron",
			given_name_birth: "Augusta Ada",
			birth_country: "GB",
			birth_city: "London",
			resident_address: "12 St. James's Square, London",
			resident_country: "GB",
			resident_city: "London",
			resident_postal_code: "SW1Y 4LB",
			resident_street: "St. James's Square",
			resident_house_number: "12",
			gender: 2,
			nationality: "GB",
			issuance_date: "2026-01-01",
			expiry_date: "2031-01-01",
			issuing_authority: "GB",
			issuing_country: "GB",
			document_number: "PID-GB-1815-ADA-01",
			administrative_number: "GB-ADM-0001",
		},
		createdAt: PREDEFINED_TEMPLATE_TIMESTAMP,
		updatedAt: PREDEFINED_TEMPLATE_TIMESTAMP,
	}),
] satisfies Template[];

export function getPredefinedTemplateById(templateId: string) {
	return PREDEFINED_TEMPLATES.find((template) => template.id === templateId);
}
