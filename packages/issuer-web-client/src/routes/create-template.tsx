import { useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "../components/layout.tsx";
import { TemplateForm } from "../components/template-form.tsx";
import { api } from "../lib/api.ts";
import { authClient } from "../lib/auth.ts";

export function CreateTemplatePage() {
	const navigate = useNavigate();
	const { data, isPending } = authClient.useSession();
	const [templateName, setTemplateName] = useState("");
	const [templateVct, setTemplateVct] = useState("");
	const [templateClaims, setTemplateClaims] = useState(
		JSON.stringify({ given_name: "Ada", family_name: "Lovelace" }, null, 2),
	);

	useEffect(() => {
		if (isPending) {
			return;
		}
		if (!data?.user) {
			void navigate({ to: "/signin" });
		}
	}, [data?.user, isPending, navigate]);

	return (
		<PageShell
			title="Create template"
			description="Define a reusable credential template and default claims for future issuances."
			back={{ to: "/", label: "Back to overview" }}
		>
			{isPending || !data?.user ? (
				<p className="text-sm text-muted-foreground">Loading...</p>
			) : (
				<TemplateForm
					claims={templateClaims}
					name={templateName}
					onClaimsChange={setTemplateClaims}
					onNameChange={setTemplateName}
					onSubmit={() => {
						void (async () => {
							const response = await api.createTemplate({
								name: templateName,
								vct: templateVct,
								defaultClaims: JSON.parse(templateClaims),
							});
							if (response.ok) {
								void navigate({ to: "/" });
							}
						})();
					}}
					onVctChange={setTemplateVct}
					vct={templateVct}
				/>
			)}
		</PageShell>
	);
}
