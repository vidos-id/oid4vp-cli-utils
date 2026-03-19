import { createHash, randomBytes } from "node:crypto";

export const nowInSeconds = () => Math.floor(Date.now() / 1000);

export const randomToken = () => randomBytes(24).toString("base64url");

export const sha256Base64Url = (value: string) =>
	createHash("sha256").update(value).digest("base64url");

export const cloneJson = <T>(value: T): T => structuredClone(value);

export const toBase64Url = (input: Uint8Array) =>
	Buffer.from(input).toString("base64url");

export const fromBase64Url = (input: string) =>
	new Uint8Array(Buffer.from(input, "base64url"));

export const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
