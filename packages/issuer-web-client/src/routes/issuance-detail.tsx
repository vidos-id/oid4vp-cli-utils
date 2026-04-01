import { useNavigate, useParams } from "@tanstack/react-router";
import type { IssuanceDetail } from "@vidos-id/issuer-web-shared";
import { useEffect, useRef, useState } from "react";
import { IssuanceDetailCard } from "../components/issuance-detail.tsx";
import { PageShell } from "../components/layout.tsx";
import { api } from "../lib/api.ts";
import { authClient } from "../lib/auth.ts";

const TERMINAL_STATES = new Set(["redeemed", "expired", "redemption_failed"]);

export function IssuanceDetailPage() {
	const navigate = useNavigate();
	const { issuanceId } = useParams({ from: "/issuances/$issuanceId" });
	const { data, isPending } = authClient.useSession();
	const [detail, setDetail] = useState<IssuanceDetail | null>(null);
	const intervalRef = useRef<number | null>(null);

	useEffect(() => {
		if (isPending) {
			return;
		}
		if (!data?.user) {
			void navigate({ to: "/signin" });
			return;
		}

		const refreshDetail = () => {
			void (async () => {
				const response = await api.getIssuance(issuanceId);
				if (response.ok) {
					const next = (await response.json()) as IssuanceDetail;
					setDetail(next);
					// Stop polling once the issuance reaches a terminal state
					if (
						TERMINAL_STATES.has(next.issuance.state) &&
						intervalRef.current !== null
					) {
						window.clearInterval(intervalRef.current);
						intervalRef.current = null;
					}
				}
			})();
		};

		refreshDetail();
		intervalRef.current = window.setInterval(refreshDetail, 2000);
		return () => {
			if (intervalRef.current !== null) {
				window.clearInterval(intervalRef.current);
				intervalRef.current = null;
			}
		};
	}, [data?.user, issuanceId, isPending, navigate]);

	return (
		<PageShell
			title="Issuance detail"
			description={
				detail ? `Credential type: ${detail.issuance.vct}` : undefined
			}
			back={{ to: "/", label: "Back to overview" }}
		>
			{isPending || !data?.user || !detail ? (
				<p className="text-sm text-muted-foreground">Loading issuance...</p>
			) : (
				<IssuanceDetailCard detail={detail} />
			)}
		</PageShell>
	);
}
