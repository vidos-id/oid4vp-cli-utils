import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { generateText } from "ai";

const version = process.argv[2];

if (!version) {
	throw new Error("Expected release version as the first argument.");
}

const apiKey = process.env.OPENCODE_ZEN_API_KEY;

if (!apiKey) {
	throw new Error("Missing OPENCODE_ZEN_API_KEY.");
}

const model = process.env.OPENCODE_ZEN_MODEL ?? "mimo-v2-pro-free";

function runGit(args: string[], allowFailure = false): string {
	const result = Bun.spawnSync(["git", ...args], {
		stdout: "pipe",
		stderr: "pipe",
	});

	if (result.exitCode !== 0) {
		if (allowFailure) {
			return "";
		}

		throw new Error(
			Buffer.from(result.stderr).toString("utf8").trim() ||
				`git ${args.join(" ")} failed`,
		);
	}

	return Buffer.from(result.stdout).toString("utf8").trim();
}

function unwrapMarkdownFence(markdown: string): string {
	const fenced = markdown.match(/^```(?:markdown|md)?\n([\s\S]*?)\n```$/);
	const unwrappedMarkdown = fenced?.[1];
	return unwrappedMarkdown ? unwrappedMarkdown.trim() : markdown.trim();
}

const opencodeZen = createOpenAICompatible({
	name: "opencode-zen",
	baseURL: "https://opencode.ai/zen/v1",
	apiKey,
});

const skillInstructions = await Bun.file(
	".agents/skills/generate-release-notes/SKILL.md",
).text();

const lastTag = runGit(
	["describe", "--tags", "--abbrev=0", "--match", "v*"],
	true,
);
const revisionRange = lastTag ? `${lastTag}..HEAD` : "HEAD";
const commitLog = runGit([
	"log",
	revisionRange,
	"--format=%h%x09%s%x0a%b%x0a---",
	"--no-merges",
]);
const changedFiles = runGit(["diff", "--name-only", revisionRange], true);

const systemPrompt = [
	"You write concise software release notes.",
	"Return markdown only.",
	`Use this exact title: # Release v${version}`,
	"Follow the provided repository skill instructions exactly.",
	"Do not invent changes that are not supported by the git data.",
	"Do not include any prose before or after the markdown document.",
].join("\n");

const userPrompt = [
	"Repository skill instructions:",
	skillInstructions,
	"",
	`Target release version: v${version}`,
	lastTag ? `Previous tag: ${lastTag}` : "Previous tag: none",
	"",
	"Changed files:",
	changedFiles || "- none",
	"",
	"Commits since the previous tag:",
	commitLog || "- none",
].join("\n");

const { text } = await generateText({
	model: opencodeZen.chatModel(model),
	system: systemPrompt,
	prompt: userPrompt,
	temperature: 0.2,
	maxRetries: 1,
});

const generatedNotes = unwrapMarkdownFence(text);

if (!generatedNotes) {
	throw new Error("OpenCode Zen returned an empty release note body.");
}

await Bun.write(".release_notes.md", `${generatedNotes}\n`);
