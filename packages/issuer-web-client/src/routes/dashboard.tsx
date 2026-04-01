import { Link, useRouter } from "@tanstack/react-router";
import type { IssuanceDetail, Template } from "@vidos-id/issuer-web-shared";
import {
	ACTIVE_TOKEN_STATUS,
	getTokenStatusLabel,
	REVOKED_TOKEN_STATUS,
	SUSPENDED_TOKEN_STATUS,
} from "@vidos-id/issuer-web-shared";
import { ChevronDown, ChevronUp, ShieldCheck } from "lucide-react";
import type { Dispatch, SetStateAction } from "react";
import { useEffect, useState } from "react";
import { AuthForm } from "../components/auth-form.tsx";
import { IssuanceList } from "../components/issuance-list.tsx";
import { PageShell, Section } from "../components/layout.tsx";
import { TemplateList } from "../components/template-list.tsx";
import type { BadgeVariant } from "../components/ui/badge.tsx";
import { Badge } from "../components/ui/badge.tsx";
import { Button } from "../components/ui/button.tsx";
import { api } from "../lib/api.ts";
import { loadDashboardData } from "../lib/app-state.ts";
import { authClient, linkAnonymousAccount } from "../lib/auth.ts";

function statusVariant(status: number) {
	const label = getTokenStatusLabel(status as 0 | 1 | 2);
	if (label === "active") return "active" as const;
	if (label === "suspended") return "suspended" as const;
	if (label === "revoked") return "revoked" as const;
	return "default" as const;
}

function getAvailableStatusActions(status: number) {
	if (status === ACTIVE_TOKEN_STATUS) {
		return [SUSPENDED_TOKEN_STATUS, REVOKED_TOKEN_STATUS] as const;
	}
	if (status === SUSPENDED_TOKEN_STATUS) {
		return [ACTIVE_TOKEN_STATUS, REVOKED_TOKEN_STATUS] as const;
	}
	return [ACTIVE_TOKEN_STATUS, SUSPENDED_TOKEN_STATUS] as const;
}

function getStatusActionLabel(status: number) {
	if (status === ACTIVE_TOKEN_STATUS) {
		return "Activate";
	}
	if (status === SUSPENDED_TOKEN_STATUS) {
		return "Suspend";
	}
	return "Revoke";
}

const ISSUANCE_STATE_LABELS = {
	offered: "Offered",
	redeeming: "Redeeming",
	redeemed: "Redeemed",
	expired: "Expired",
	redemption_failed: "Redemption failed",
} as const;

type IssuanceState = keyof typeof ISSUANCE_STATE_LABELS;

const STATE_BADGE_VARIANTS: Record<IssuanceState, BadgeVariant> = {
	offered: "state-offered",
	redeeming: "state-redeeming",
	redeemed: "state-redeemed",
	expired: "state-expired",
	redemption_failed: "state-failed",
};

async function refreshDashboardData(
	setTemplates: Dispatch<SetStateAction<Template[]>>,
	setIssuances: Dispatch<SetStateAction<IssuanceDetail["issuance"][]>>,
) {
	const next = await loadDashboardData();
	setTemplates(next.templates);
	setIssuances(next.issuances);
}

function IssuanceRow(props: {
	issuance: IssuanceDetail["issuance"];
	onUpdateStatus: (issuanceId: string, status: 0 | 1 | 2) => void;
}) {
	const { issuance, onUpdateStatus } = props;

	return (
		<div className="flex flex-col gap-4 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
			<div className="min-w-0 flex-1">
				<Link
					to="/issuances/$issuanceId"
					params={{ issuanceId: issuance.id }}
					className="block transition-colors hover:text-foreground"
				>
					<p className="text-sm font-medium">{issuance.vct}</p>
				</Link>
				<div className="mt-2 flex flex-wrap items-center gap-1.5">
					<Badge variant={STATE_BADGE_VARIANTS[issuance.state]}>
						{ISSUANCE_STATE_LABELS[issuance.state]}
					</Badge>
					{issuance.status !== ACTIVE_TOKEN_STATUS ? (
						<Badge variant={statusVariant(issuance.status)}>
							{getTokenStatusLabel(issuance.status)}
						</Badge>
					) : null}
				</div>
			</div>
			<div className="flex shrink-0 flex-wrap gap-1.5">
				{getAvailableStatusActions(issuance.status).map((status) => (
					<Button
						key={status}
						variant="outline"
						size="sm"
						onClick={() => onUpdateStatus(issuance.id, status)}
						type="button"
						className={
							status === REVOKED_TOKEN_STATUS
								? "text-destructive hover:text-destructive"
								: undefined
						}
					>
						{getStatusActionLabel(status)}
					</Button>
				))}
			</div>
		</div>
	);
}

export function DashboardPage() {
	const router = useRouter();
	const { data, isPending } = authClient.useSession();
	const [templates, setTemplates] = useState<Template[]>([]);
	const [issuances, setIssuances] = useState<IssuanceDetail["issuance"][]>([]);

	useEffect(() => {
		if (isPending) {
			return;
		}
		if (!data?.user) {
			void router.navigate({ to: "/signin" });
			return;
		}
		const refresh = () => {
			void refreshDashboardData(setTemplates, setIssuances);
		};
		refresh();
		const interval = window.setInterval(refresh, 2000);
		return () => window.clearInterval(interval);
	}, [data?.user, isPending, router]);

	const isAnonymous =
		data?.user && "isAnonymous" in data.user && Boolean(data.user.isAnonymous);
	const openIssuances = issuances.filter(
		(issuance) => issuance.state !== "redeemed",
	);
	const redeemedIssuances = issuances.filter(
		(issuance) => issuance.state === "redeemed",
	);

	const description =
		isPending || !data?.user
			? undefined
			: isAnonymous
				? "You are using a guest workspace. Everything here is temporary until you link an account."
				: "Issue verifiable credentials from your templates.";

	return (
		<PageShell title="Overview" description={description}>
			{isPending || !data?.user ? (
				<p className="text-sm text-muted-foreground">Loading...</p>
			) : (
				<>
					{isAnonymous ? <LinkAccountCard router={router} /> : null}

					<div className="space-y-10">
						<Section
							title="Templates"
							description="Choose a template to open a prefilled issuance flow, or delete custom templates you no longer need."
							actions={
								<Button
									variant="outline"
									type="button"
									onClick={() => {
										void router.navigate({ to: "/templates/create" });
									}}
								>
									Create template
								</Button>
							}
						>
							<TemplateList
								templates={templates}
								onDelete={(templateId) => {
									void (async () => {
										const response = await api.deleteTemplate(templateId);
										if (response.ok) {
											await refreshDashboardData(setTemplates, setIssuances);
										}
									})();
								}}
								onUseTemplate={(templateId) => {
									void router.navigate({
										to: "/issuances/create/$templateId",
										params: { templateId },
									});
								}}
								showDelete
							/>
						</Section>

						<Section
							title="Redeemed credentials"
							description="Manage status for credentials that have already been claimed by a wallet."
						>
							{redeemedIssuances.length === 0 ? (
								<IssuanceList issuances={redeemedIssuances} />
							) : (
								<div className="divide-y rounded-md border">
									{redeemedIssuances.map((issuance) => (
										<IssuanceRow
											key={issuance.id}
											issuance={issuance}
											onUpdateStatus={updateIssuanceStatus}
										/>
									))}
								</div>
							)}
						</Section>

						<Section
							title="Open offers"
							description="Track credential offers live while they move from offered to redeemed, or expire before redemption."
						>
							{openIssuances.length === 0 ? (
								<IssuanceList issuances={openIssuances} />
							) : (
								<div className="divide-y rounded-md border">
									{openIssuances.map((issuance) => (
										<IssuanceRow
											key={issuance.id}
											issuance={issuance}
											onUpdateStatus={updateIssuanceStatus}
										/>
									))}
								</div>
							)}
						</Section>
					</div>
				</>
			)}
		</PageShell>
	);

	function updateIssuanceStatus(issuanceId: string, status: 0 | 1 | 2) {
		void (async () => {
			const response = await api.updateIssuanceStatus(issuanceId, { status });
			if (response.ok) {
				await refreshDashboardData(setTemplates, setIssuances);
			}
		})();
	}
}

function LinkAccountCard(props: { router: ReturnType<typeof useRouter> }) {
	const [expanded, setExpanded] = useState(false);
	const [linked, setLinked] = useState(false);
	const [linkUsername, setLinkUsername] = useState("");
	const [linkPassword, setLinkPassword] = useState("");
	const [linkConfirmPassword, setLinkConfirmPassword] = useState("");
	const [linkMessage, setLinkMessage] = useState<string | null>(null);
	const [linkLoading, setLinkLoading] = useState(false);

	if (linked) {
		return (
			<div
				id="link-account"
				className="mb-8 flex items-center gap-3 rounded-lg border border-status-active/30 bg-status-active/5 px-5 py-4"
			>
				<ShieldCheck className="h-5 w-5 shrink-0 text-status-active" />
				<div>
					<p className="text-sm font-medium">Account linked</p>
					<p className="text-xs text-muted-foreground">
						Your guest workspace has been saved. You can now sign in with your
						username and password.
					</p>
				</div>
			</div>
		);
	}

	return (
		<div id="link-account" className="mb-8 rounded-lg border bg-card">
			<button
				type="button"
				className="flex w-full items-center justify-between px-5 py-4 text-left"
				onClick={() => setExpanded((prev) => !prev)}
			>
				<div>
					<p className="text-sm font-medium">Save your guest workspace</p>
					<p className="text-xs text-muted-foreground">
						Link a username and password to keep your templates and issuances.
					</p>
				</div>
				{expanded ? (
					<ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
				) : (
					<ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
				)}
			</button>

			{expanded ? (
				<div className="border-t px-5 pb-5 pt-4">
					<div className="max-w-sm">
						<AuthForm
							mode="signup"
							name={linkUsername}
							password={linkPassword}
							confirmPassword={linkConfirmPassword}
							message={linkMessage}
							disabled={linkLoading}
							submitLabel="Link account"
							onNameChange={setLinkUsername}
							onPasswordChange={setLinkPassword}
							onConfirmPasswordChange={setLinkConfirmPassword}
							onSubmit={() => {
								void (async () => {
									setLinkMessage(null);
									const username = linkUsername.trim();
									if (!username || !linkPassword) {
										setLinkMessage("Enter a username and password");
										return;
									}
									if (linkPassword !== linkConfirmPassword) {
										setLinkMessage("Passwords do not match");
										return;
									}
									setLinkLoading(true);
									try {
										const result = await linkAnonymousAccount({
											username,
											password: linkPassword,
										});
										if (result.error) {
											setLinkMessage(
												result.error.message ?? "Could not link account",
											);
											return;
										}
										setLinked(true);
										void props.router.invalidate();
									} finally {
										setLinkLoading(false);
									}
								})();
							}}
						/>
					</div>
				</div>
			) : null}
		</div>
	);
}
