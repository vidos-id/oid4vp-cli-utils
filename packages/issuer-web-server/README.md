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

## Environment

- `ISSUER_WEB_PORT`
- `ISSUER_WEB_ORIGIN`
- `ISSUER_WEB_CLIENT_ORIGIN`
- `ISSUER_WEB_CLIENT_ORIGINS` comma-separated extra trusted browser origins
- `ISSUER_WEB_DATABASE_PATH`
- `ISSUER_WEB_AUTH_SECRET`
