import { useEffect, useState } from "react";
import { AuthForm } from "../components/auth-form.tsx";
import { PageShell } from "../components/layout.tsx";
import { Button } from "../components/ui/button.tsx";
import {
	authClient,
	signInAnonymously,
	signInWithUsername,
	signUpWithUsername,
} from "../lib/auth.ts";

type AuthMode = "signin" | "signup";

export function AuthPage(props: { mode: AuthMode }) {
	const { data, isPending } = authClient.useSession();
	const [name, setName] = useState("");
	const [password, setPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [message, setMessage] = useState<string | null>(null);
	const [submitting, setSubmitting] = useState(false);
	const [anonymousMessage, setAnonymousMessage] = useState<string | null>(null);
	const [anonymousLoading, setAnonymousLoading] = useState(false);

	useEffect(() => {
		if (isPending || !data?.user) {
			return;
		}
		window.location.assign("/");
	}, [data?.user, isPending]);

	return (
		<PageShell
			title={props.mode === "signup" ? "Create account" : "Sign in"}
			description="Free demo access for testing. No obligation, and data persistence is not guaranteed."
		>
			<div className="max-w-sm space-y-6">
				{props.mode === "signin" ? (
					<>
						{/* Anonymous option first - primary action for quick start */}
						<div className="rounded-lg border bg-card p-5">
							<div className="mb-4">
								<p className="text-sm font-medium">Quick start</p>
								<p className="mt-1 text-xs text-muted-foreground">
									Jump in without an account. You can save your work later by
									linking a username and password.
								</p>
							</div>
							<Button
								type="button"
								className="w-full"
								disabled={anonymousLoading}
								onClick={() => {
									void (async () => {
										setMessage(null);
										setAnonymousMessage(null);
										setAnonymousLoading(true);
										try {
											const result = await signInAnonymously();
											if (result.error) {
												setAnonymousMessage(
													result.error.message ??
														"Could not start guest session",
												);
												return;
											}
											window.location.assign("/");
										} finally {
											setAnonymousLoading(false);
										}
									})();
								}}
							>
								{anonymousLoading ? "Starting..." : "Continue as guest"}
							</Button>
							{anonymousMessage ? (
								<p className="mt-3 text-xs text-destructive">
									{anonymousMessage}
								</p>
							) : null}
						</div>

						{/* Divider */}
						<div className="flex items-center gap-3">
							<div className="h-px flex-1 bg-border" />
							<span className="text-xs text-muted-foreground">
								or sign in with credentials
							</span>
							<div className="h-px flex-1 bg-border" />
						</div>
					</>
				) : null}

				{/* Username/password form */}
				<AuthForm
					mode={props.mode}
					name={name}
					password={password}
					confirmPassword={confirmPassword}
					message={message}
					disabled={submitting}
					alternateHref={props.mode === "signup" ? "/signin" : "/signup"}
					alternateLabel={
						props.mode === "signup"
							? "Already have an account?"
							: "Create an account"
					}
					onNameChange={setName}
					onPasswordChange={setPassword}
					onConfirmPasswordChange={setConfirmPassword}
					onSubmit={() => {
						void (async () => {
							setMessage(null);
							setAnonymousMessage(null);
							const username = name.trim();
							if (!username || !password) {
								setMessage("Enter a username and password");
								return;
							}
							if (props.mode === "signup" && password !== confirmPassword) {
								setMessage("Passwords do not match");
								return;
							}
							setSubmitting(true);
							try {
								const result =
									props.mode === "signup"
										? await signUpWithUsername({ username, password })
										: await signInWithUsername({ username, password });
								if (result.error) {
									setMessage(result.error.message ?? "Authentication failed");
									return;
								}
								window.location.assign("/");
							} finally {
								setSubmitting(false);
							}
						})();
					}}
				/>
			</div>
		</PageShell>
	);
}
