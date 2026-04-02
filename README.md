# openid4vc-tools

[![Release](https://img.shields.io/github/actions/workflow/status/vidos-id/openid4vc-tools/release.yml?branch=main&label=release)](https://github.com/vidos-id/openid4vc-tools/actions/workflows/release.yml) [![npm issuer](https://img.shields.io/npm/v/%40vidos-id%2Fopenid4vc-issuer?label=issuer)](https://www.npmjs.com/package/@vidos-id/openid4vc-issuer) [![npm wallet](https://img.shields.io/npm/v/%40vidos-id%2Fopenid4vc-wallet?label=wallet)](https://www.npmjs.com/package/@vidos-id/openid4vc-wallet) [![npm issuer-cli](https://img.shields.io/npm/v/%40vidos-id%2Fopenid4vc-issuer-cli?label=issuer-cli)](https://www.npmjs.com/package/@vidos-id/openid4vc-issuer-cli) [![npm wallet-cli](https://img.shields.io/npm/v/%40vidos-id%2Fopenid4vc-wallet-cli?label=wallet-cli)](https://www.npmjs.com/package/@vidos-id/openid4vc-wallet-cli)

Tools for testing OpenID4VC flows across issuer and wallet roles.

This repo contains libraries, CLI wrappers, and web applications that can be used to exercise credential issuance, wallet receipt and storage, and OpenID4VP presentation flows.

Current focus:

- issuer-side testing with a small issuer library and issuer web app
- wallet-side testing with a wallet library and terminal wallet flows
- end-to-end demos for OpenID4VCI and OpenID4VP-style interactions
- scriptable tooling suitable for local development, demos, and protocol exploration

## Packages

| Package | Description |
|---------|-------------|
| [`@vidos-id/openid4vc-issuer`](packages/issuer/) | Issuer library for test and demo issuance flows |
| [`@vidos-id/openid4vc-wallet`](packages/wallet/) | Wallet library for receipt, storage, and presentation flows |
| [`@vidos-id/openid4vc-issuer-cli`](packages/issuer-cli/) | Terminal client for the issuer web server |
| [`@vidos-id/openid4vc-wallet-cli`](packages/wallet-cli/) | Terminal wallet for receive, inspect, and present flows |
| [`@vidos-id/openid4vc-issuer-web-server`](packages/issuer-web-server/) | Bun + Hono issuer API for the web app and CLI |
| [`@vidos-id/openid4vc-issuer-web-client`](packages/issuer-web-client/) | React web app for issuer-side testing workflows |
| [`@vidos-id/openid4vc-issuer-web-shared`](packages/issuer-web-shared/) | Shared types and schemas for the issuer web packages |
| [`@vidos-id/openid4vc-cli-common`](packages/cli-common/) | Shared CLI helpers |

## Install

Published packages use the `@vidos-id` scope on npmjs.

Requirements:

- [Bun](https://bun.sh/) installed

### Libraries

```bash
# bun
bun add @vidos-id/openid4vc-wallet @vidos-id/openid4vc-issuer

# npm
npm install @vidos-id/openid4vc-wallet @vidos-id/openid4vc-issuer

# pnpm
pnpm add @vidos-id/openid4vc-wallet @vidos-id/openid4vc-issuer

# yarn
yarn add @vidos-id/openid4vc-wallet @vidos-id/openid4vc-issuer
```

### CLIs

```bash
# bun
bun install -g @vidos-id/openid4vc-wallet-cli @vidos-id/openid4vc-issuer-cli

# npm
npm install -g @vidos-id/openid4vc-wallet-cli @vidos-id/openid4vc-issuer-cli
```

## Local Dev

```bash
bun install
bun run dev:issuer-web
```

Or run individual entry points:

```bash
bun run --filter '@vidos-id/openid4vc-issuer-web-server' dev
bun run --filter '@vidos-id/openid4vc-issuer-web-client' dev
bun packages/issuer-cli/src/cli.ts --help
bun packages/wallet-cli/src/cli.ts --help
```

## Demos

```bash
bun scripts/demo-e2e.ts
bun scripts/demo-oid4vci-e2e.ts
```

Example payloads live in [`examples/pid/`](examples/pid/).

## Docs

- issuer library: [`packages/issuer/README.md`](packages/issuer/README.md)
- wallet library: [`packages/wallet/README.md`](packages/wallet/README.md)
- issuer CLI: [`packages/issuer-cli/README.md`](packages/issuer-cli/README.md)
- wallet CLI: [`packages/wallet-cli/README.md`](packages/wallet-cli/README.md)
- issuer web server: [`packages/issuer-web-server/README.md`](packages/issuer-web-server/README.md)
- issuer web client: [`packages/issuer-web-client/README.md`](packages/issuer-web-client/README.md)

## Validate

```bash
bun test
bun run check-types
bun run lint
```
