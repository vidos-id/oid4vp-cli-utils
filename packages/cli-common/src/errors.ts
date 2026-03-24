import { ZodError } from "zod";

export function handleCliError(error: unknown): never {
	if (error instanceof ZodError) {
		process.stderr.write(`${formatZodError(error)}\n`);
		process.exit(1);
	}
	const message = error instanceof Error ? error.message : String(error);
	process.stderr.write(`${message}\n`);
	process.exit(1);
}

export function formatZodError(error: ZodError): string {
	return error.issues
		.map((issue) => {
			const path = issue.path.length > 0 ? issue.path.join(".") : "input";
			return `${path}: ${issue.message}`;
		})
		.join("\n");
}
