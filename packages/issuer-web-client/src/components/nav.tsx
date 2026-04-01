import { Link, useRouter } from "@tanstack/react-router";
import { UserRound } from "lucide-react";
import { authClient } from "../lib/auth.ts";
import { cn } from "../lib/cn.ts";
import { Badge } from "./ui/badge.tsx";
import { ThemeToggle } from "./ui/theme-toggle.tsx";

export function AppHeader() {
	const router = useRouter();
	const { data } = authClient.useSession();
	const isAnonymous =
		data?.user && "isAnonymous" in data.user && Boolean(data.user.isAnonymous);

	return (
		<header className="border-b">
			<div className="mx-auto flex h-14 max-w-5xl items-center gap-6 px-6">
				<Link to="/" className="text-sm font-semibold tracking-tight">
					Vidos Demo Issuer
				</Link>

				{data?.user ? (
					<>
						<nav className="flex items-center gap-1">
							<NavLink to="/">Overview</NavLink>
							<NavLink to="/metadata">Metadata</NavLink>
						</nav>

						<div className="ml-auto flex items-center gap-3">
							<ThemeToggle />

							{isAnonymous ? (
								<GuestIndicator />
							) : (
								<span className="text-xs text-muted-foreground">
									{"username" in data.user && data.user.username
										? data.user.username
										: data.user.name}
								</span>
							)}

							<button
								type="button"
								onClick={() => {
									void authClient
										.signOut()
										.then(() => router.navigate({ to: "/signin" }));
								}}
								className="h-8 rounded-md border px-3 text-xs font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
							>
								Sign out
							</button>
						</div>
					</>
				) : (
					<div className="ml-auto flex items-center gap-3">
						<ThemeToggle />
						<Link
							to="/signin"
							className="h-8 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
						>
							Sign in
						</Link>
						<Link
							to="/signup"
							className="h-8 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
						>
							Sign up
						</Link>
					</div>
				)}
			</div>
		</header>
	);
}

function GuestIndicator() {
	return (
		<span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
			<UserRound className="h-3.5 w-3.5" />
			<span>Guest</span>
			<Badge variant="secondary" className="ml-0.5">
				temporary
			</Badge>
		</span>
	);
}

function NavLink(props: { to: string; children: React.ReactNode }) {
	return (
		<Link
			to={props.to}
			activeOptions={{ exact: true }}
			activeProps={{ className: "text-foreground" }}
			className={cn(
				"rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground",
			)}
		>
			{props.children}
		</Link>
	);
}
