let verboseEnabled = false;

export function setVerbose(enabled: boolean): void {
	verboseEnabled = enabled;
}

export function isVerbose(): boolean {
	return verboseEnabled;
}

export function verbose(message: string): void {
	if (verboseEnabled) {
		process.stderr.write(`[verbose] ${message}\n`);
	}
}
