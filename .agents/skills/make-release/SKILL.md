---
name: make-release
description: Create a versioned release with GitHub tag and release artifacts. Use this skill whenever the user wants to release, cut a release, bump a version, tag a version, publish a new version, ship a release, or asks about the release process. Also use when the user says things like "let's release", "prepare a release", "make a new version", or "we're ready to ship".
---

# Release

This skill walks through creating a versioned GitHub release for this monorepo. The release workflow (`.github/workflows/release.yml`) triggers on `v*` tags, publishes the scoped `@vidos-id/*` packages to GitHub Packages with `bun publish`, and produces bundled CLI artifacts (`wallet-cli.js`, `issuer-cli.js`) attached to a GitHub Release.

## The release flow

### 1. Determine the next version

Read the current version from the root `package.json` and find the last released tag:

```bash
git tag --list 'v*' --sort=-v:refname | head -5
```

### 2. Analyze changes and suggest version bump

Run the full commit log since the last tag:

```bash
git log <last_tag>..HEAD --format="%s%n%b---" --no-merges
```

Classify the changes:

- **patch** (0.0.x): bug fixes, docs, refactors, dependency updates, chore
- **minor** (0.x.0): new features, new CLI commands, new options, non-breaking API additions
- **major** (x.0.0): breaking changes to CLI interface (renamed/removed commands or flags), breaking changes to library APIs, dropped compatibility

Based on this analysis, suggest whether the bump should be **patch**, **minor**, or **major**. Present this recommendation to the developer and ask for confirmation before proceeding.

### 3. Apply the version bump

After confirming the bump type, update the version in all `package.json` files:

- `package.json` (root)
- `packages/cli-common/package.json`
- `packages/issuer/package.json`
- `packages/issuer-cli/package.json`
- `packages/wallet/package.json`
- `packages/wallet-cli/package.json`

### 4. Generate release notes

Read the full commit messages for all commits since the last tag:

```bash
git log <last_tag>..HEAD --format="%s%n%b---" --no-merges
```

Then generate a human-readable changelog overview in markdown format with sections for:
- **Highlights** (most important changes, 2-4 bullet points)
- **New Features** (if any minor-level changes)
- **Bug Fixes** (if any patch-level fixes)
- **Other Changes** (docs, refactors, chores, dependency updates)

Write the generated notes to `.release_notes.md` in the repo root. These will be used by the release workflow.

### 5. Pre-release checks

Before tagging, verify the codebase is healthy:

```bash
bun run check-types
bun test
bun run build
```

Also verify the bundled CLIs actually work:

```bash
bun dist/wallet-cli/index.js --help
bun dist/issuer-cli/index.js --help
```

If any of these fail, stop and fix the issues before releasing.

Before releasing, confirm the package metadata is publishable:

- package names are scoped to `@vidos-id/*`
- every published package has the same version
- package publishing still works with Bun's `workspace:*` resolution for local dependencies
- each package points `publishConfig.registry` to `https://npm.pkg.github.com`
- each package includes the repo URL in its `repository` field

### 6. Tag and push

Create the git tag and push it. This triggers the release workflow in CI:

```bash
git tag v<version>
git push origin v<version>
```

### 7. Verify the release and package publish

Check that the GitHub Actions workflow started and completed:

```bash
gh run list --limit 1
```

Then confirm the release was created with the expected artifacts:

```bash
gh release view v<version>
```

You should see both `wallet-cli.js` and `issuer-cli.js` listed as assets.

Also verify the GitHub Packages publish succeeded for:

- `@vidos-id/cli-common`
- `@vidos-id/issuer`
- `@vidos-id/issuer-cli`
- `@vidos-id/wallet`
- `@vidos-id/wallet-cli`

Important notes for this repository:

- packages are intentionally published as raw TypeScript right now, not prebuilt JS
- packages are published via Bun using the `NPM_CONFIG_TOKEN` secret exposed as `NPM_CONFIG_TOKEN` in CI
- consumers still need GitHub Packages auth and an `.npmrc` or `bunfig.toml` entry for the `@vidos-id` scope, even when the packages are public
