---
name: make-release
description: Create a versioned release with GitHub tag and release artifacts. Use this skill whenever the user wants to release, cut a release, bump a version, tag a version, publish a new version, ship a release, or asks about the release process. Also use when the user says things like "let's release", "prepare a release", "make a new version", or "we're ready to ship".
---

# Release

This skill walks through creating a versioned GitHub release for this monorepo. The release workflow (`.github/workflows/release.yml`) triggers on `v*` tags and produces bundled CLI artifacts (`wallet-cli.js`, `issuer-cli.js`) attached to a GitHub Release.

## The release flow

### 1. Determine the next version

Read the current version from the root `package.json`. This is the version that will be released (it should already reflect what you're about to ship).

### 2. Analyze changes since the last release

Run `git log --oneline` from the last tag to HEAD to see what's changed. Look at the commit messages and classify them:

- **patch** (0.0.x): bug fixes, docs, refactors, dependency updates, chore
- **minor** (0.x.0): new features, new CLI commands, new options, non-breaking API additions
- **major** (x.0.0): breaking changes to CLI interface (renamed/removed commands or flags), breaking changes to library APIs, dropped compatibility

Compare this against the version bump implied by the current version in `package.json` relative to the last released tag. If the changes suggest a bigger bump is needed (e.g., there's a breaking change but the version only bumped the patch), flag this to the developer and ask for confirmation before proceeding.

### 3. Pre-release checks

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

### 4. Ensure versions are consistent

All `package.json` files in the monorepo should have the same version. Check:
- `package.json` (root)
- `packages/cli-common/package.json`
- `packages/issuer/package.json`
- `packages/issuer-cli/package.json`
- `packages/wallet/package.json`
- `packages/wallet-cli/package.json`

If they're out of sync, align them to the release version before proceeding.

### 5. Tag and push

Create the git tag and push it. This triggers the release workflow in CI:

```bash
git tag v<version>
git push origin v<version>
```

### 6. Verify the release

Check that the GitHub Actions workflow started and completed:

```bash
gh run list --limit 1
```

Then confirm the release was created with the expected artifacts:

```bash
gh release view v<version>
```

You should see both `wallet-cli.js` and `issuer-cli.js` listed as assets.

### 7. Version bump decision

After a successful release, the version in `package.json` represents the version that was just released. There is no need to pre-bump to the next development version -- the version stays as-is until the next release is prepared.

When the developer is ready for the next release, they (or this skill) will bump the version at that point as part of the release preparation.
