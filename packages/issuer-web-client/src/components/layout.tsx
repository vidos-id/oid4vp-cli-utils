import { Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { cn } from "../lib/cn.ts";

/**
 * Shared page shell that every route should use.
 *
 * Renders an optional back-link, the page header, and the body content in a
 * consistent layout so page transitions never shift width or vertical position.
 */
export function PageShell(props: {
	title: string;
	description?: string;
	actions?: React.ReactNode;
	/** Render a "Back to ..." link above the header. */
	back?: { to: string; label: string };
	children?: React.ReactNode;
}) {
	return (
		<div className="space-y-8">
			{/* Back link --------------------------------------------------------- */}
			{/* Reserve a fixed-height slot so the header never shifts vertically. */}
			<div className="min-h-[1.25rem]">
				{props.back ? (
					<Link
						to={props.back.to}
						className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
					>
						<ArrowLeft className="h-3.5 w-3.5" />
						{props.back.label}
					</Link>
				) : null}
			</div>

			{/* Page header ------------------------------------------------------ */}
			<PageHeader
				title={props.title}
				description={props.description}
				actions={props.actions}
			/>

			{/* Page body -------------------------------------------------------- */}
			{props.children}
		</div>
	);
}

export function PageHeader(props: {
	title: string;
	description?: string;
	actions?: React.ReactNode;
}) {
	return (
		<div>
			<div className="flex items-center justify-between gap-4">
				<h1 className="text-2xl font-semibold tracking-tight">{props.title}</h1>
				{props.actions ? (
					<div className="flex gap-2">{props.actions}</div>
				) : null}
			</div>
			{props.description ? (
				<p className="mt-1 text-sm text-muted-foreground">
					{props.description}
				</p>
			) : null}
		</div>
	);
}

export function Section(props: {
	title: string;
	description?: string;
	actions?: React.ReactNode;
	children: React.ReactNode;
	className?: string;
}) {
	return (
		<section className={cn("space-y-4", props.className)}>
			<div className="flex items-center justify-between gap-4">
				<div>
					<h2 className="text-lg font-semibold tracking-tight">
						{props.title}
					</h2>
					{props.description ? (
						<p className="text-sm text-muted-foreground">{props.description}</p>
					) : null}
				</div>
				{props.actions ? (
					<div className="flex gap-2">{props.actions}</div>
				) : null}
			</div>
			{props.children}
		</section>
	);
}
