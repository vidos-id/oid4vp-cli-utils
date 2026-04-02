# @vidos-id/openid4vc-issuer-web-client

React + Vite SPA for the demo issuer web application.

This package provides the browser UI for issuer-side testing workflows. It uses the issuer web server for authentication, template management, issuance creation, and QR-based wallet handoff.

Use it when you want a visual issuer app instead of driving the same flows through `openid4vc-issuer`.

## Local Dev

Uses committed local defaults from `.env.local`:

```bash
bun run --filter '@vidos-id/openid4vc-issuer-web-client' dev
```

Run the API separately:

```bash
bun run --filter '@vidos-id/openid4vc-issuer-web-server' dev
```

Default URLs:

- app: `http://localhost:5174`
- API/server: `http://localhost:3001`

## Deployment

Build and deploy this package as a static SPA.

Recommended deployment flow:

1. Install workspace dependencies from the repo root with `bun install`.
2. Set the required `VITE_...` variables before building.
3. Build the SPA with `bun --filter '@vidos-id/openid4vc-issuer-web-client' run build`.
4. Deploy the generated `packages/issuer-web-client/dist/` directory to your static host.

Deployment notes:

- Vite injects these variables at build time, not runtime. Rebuild the SPA whenever they change.
- `VITE_ISSUER_WEB_SERVER_URL` should point at the deployed issuer web server origin used for API requests.
- `VITE_ISSUER_WEB_AUTH_URL` should normally match the server auth base URL, which is typically the same origin as the server.
- The deployed server must allow this SPA origin via `ISSUER_WEB_CLIENT_ORIGIN` or `ISSUER_WEB_CLIENT_ORIGINS`.

## Environment

All client environment validation lives in `src/env.ts`.

| Variable | Required | Purpose |
| --- | --- | --- |
| `VITE_ISSUER_WEB_SERVER_URL` | Yes | Base URL used for API requests such as `/api`, `/.well-known`, `/token`, `/credential`, and `/status-lists`. |
| `VITE_ISSUER_WEB_AUTH_URL` | Yes | Base URL passed to Better Auth in the browser for signin and session operations. |

Example production-oriented environment:

```bash
VITE_ISSUER_WEB_SERVER_URL=https://issuer.example.com
VITE_ISSUER_WEB_AUTH_URL=https://issuer.example.com
```

## Features

- TanStack React Router SPA
- Better Auth signup/signin UX
- custom template creation
- issuance list and detail routes
- QR rendering for wallet handoff

The same issuer workflows are also exposed through the CLI package for terminal-based testing.

## Routes

- `/signin`
- `/`
- `/issuances/:issuanceId`
