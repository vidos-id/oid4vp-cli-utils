import {
	createRootRoute,
	createRoute,
	createRouter,
	Outlet,
	redirect,
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { AppHeader } from "./components/nav.tsx";
import { authClient } from "./lib/auth.ts";
import { CreateIssuancePage } from "./routes/create-issuance.tsx";
import { CreateTemplatePage } from "./routes/create-template.tsx";
import { DashboardPage } from "./routes/dashboard.tsx";
import { IssuanceDetailPage } from "./routes/issuance-detail.tsx";
import { MetadataPage } from "./routes/metadata.tsx";
import { SignInPage } from "./routes/signin.tsx";
import { SignUpPage } from "./routes/signup.tsx";

const rootRoute = createRootRoute({
	component: () => (
		<div className="flex min-h-screen flex-col">
			<AppHeader />
			<main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
				<Outlet />
			</main>
			<TanStackRouterDevtools position="bottom-right" />
		</div>
	),
});

const dashboardRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/",
	component: DashboardPage,
});

const signinRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/signin",
	beforeLoad: async () => {
		const session = await authClient.getSession();
		if (session.data?.user) {
			throw redirect({ to: "/" });
		}
	},
	component: SignInPage,
});

const signupRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/signup",
	beforeLoad: async () => {
		const session = await authClient.getSession();
		if (session.data?.user) {
			throw redirect({ to: "/" });
		}
	},
	component: SignUpPage,
});

const issuanceDetailRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/issuances/$issuanceId",
	component: IssuanceDetailPage,
});

const createIssuanceRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/issuances/create/$templateId",
	component: CreateIssuancePage,
});

const createTemplateRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/templates/create",
	component: CreateTemplatePage,
});

const metadataRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/metadata",
	component: MetadataPage,
});

const routeTree = rootRoute.addChildren([
	dashboardRoute,
	signinRoute,
	signupRoute,
	createTemplateRoute,
	createIssuanceRoute,
	issuanceDetailRoute,
	metadataRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
	interface Register {
		router: typeof router;
	}
}
