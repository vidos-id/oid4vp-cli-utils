# @vidos-id/openid4vc-issuer-web-server

Hono + Bun API for the demo issuer web application.

This package backs both the issuer web client and the `openid4vc-issuer` CLI. It owns issuer-side state, authentication, template management, issuance records, and the protocol endpoints used during testing flows.

Primary responsibilities:

- expose issuer metadata and credential endpoints
- manage templates and issuances for the app and CLI
- persist issuer-side state in a local database
- provide the server surface for wallet handoff during local testing

## Local Dev

Uses committed local defaults from `.env.local`:

```bash
bun run --filter '@vidos-id/openid4vc-issuer-web-server' dev
```

Run the SPA separately:

```bash
bun run --filter '@vidos-id/openid4vc-issuer-web-client' dev
```

Default URL:

- `http://localhost:3001`

## Deployment

Deploy this package as an independent Bun service.

The web client and CLI can both target the same deployed server.

Recommended deployment flow:

1. Install workspace dependencies from the repo root with `bun install`.
2. Set the environment variables below for the deployed service.
3. Ensure the parent directory for `ISSUER_WEB_DATABASE_PATH` exists and is writable by the service.
4. Run `bun --filter '@vidos-id/openid4vc-issuer-web-server' run db:generate` when you need to regenerate Drizzle artifacts after schema changes.
5. Start the service with `bun --filter '@vidos-id/openid4vc-issuer-web-server' run dev` for a simple Bun runtime deployment, or run `bun packages/issuer-web-server/src/main.ts` from the repo root if you are wiring your own process manager.

Deployment notes:

- `ISSUER_WEB_ORIGIN` must be the public origin that wallets and browsers use to reach this server.
- Better Auth uses `ISSUER_WEB_ORIGIN` as its base URL, so mismatches will break signin and session cookies.
- CORS allows `ISSUER_WEB_CLIENT_ORIGIN` plus any origins listed in `ISSUER_WEB_CLIENT_ORIGINS`.
- The checked-in defaults are suitable for local development only. In particular, replace `ISSUER_WEB_AUTH_SECRET` in any deployed environment.

## Environment

All server configuration comes from `src/config.ts`.

| Variable | Required for deployment | Default | Purpose |
| --- | --- | --- | --- |
| `ISSUER_WEB_DATABASE_PATH` | Yes | `./.data/issuer-web.sqlite` | SQLite database path used by the service and Drizzle config. |
| `ISSUER_WEB_PORT` | Usually | `3001` | Port Bun listens on. Often provided by the hosting platform. |
| `ISSUER_WEB_ORIGIN` | Yes | `http://localhost:3001` | Public base URL for this server. Used in issuer metadata and Better Auth configuration. |
| `ISSUER_WEB_CLIENT_ORIGIN` | Yes | `http://localhost:5174` | Primary browser origin allowed to call this server with credentials. |
| `ISSUER_WEB_CLIENT_ORIGINS` | No | unset | Comma-separated list of extra trusted browser origins for CORS and auth flows. |
| `ISSUER_WEB_AUTH_SECRET` | Yes | `issuer-web-demo-secret` | Better Auth secret. Must be changed in deployed environments and must be at least 16 characters long. |
| `ISSUER_WEB_NAME` | No | `Issuer Web` | Human-readable issuer name stored in issuer configuration. |
| `ISSUER_WEB_DEFAULT_SIGNING_ALG` | No | `EdDSA` | Default signing algorithm for new issuer keys. Supported values: `ES256`, `ES384`, `EdDSA`. |
| `ISSUER_WEB_PRE_AUTHORIZED_CODE_TTL_SECONDS` | No | `3600` | Lifetime, in seconds, for pre-authorized code issuance flows. |

Example production-oriented environment:

```bash
ISSUER_WEB_PORT=3001
ISSUER_WEB_ORIGIN=https://issuer.example.com
ISSUER_WEB_CLIENT_ORIGIN=https://app.example.com
ISSUER_WEB_CLIENT_ORIGINS=https://preview.example.com
ISSUER_WEB_DATABASE_PATH=/var/lib/openid4vc/issuer-web.sqlite
ISSUER_WEB_AUTH_SECRET=replace-with-a-long-random-secret
ISSUER_WEB_NAME=Example Issuer
ISSUER_WEB_DEFAULT_SIGNING_ALG=EdDSA
ISSUER_WEB_PRE_AUTHORIZED_CODE_TTL_SECONDS=3600
```
