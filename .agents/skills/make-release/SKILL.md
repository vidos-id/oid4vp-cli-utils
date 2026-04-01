---
name: make-release
description: Create a versioned release with GitHub tag and release artifacts. Use this skill whenever the user wants to release, cut a release, bump a version, tag a version, publish a new version, ship a release, or asks about the release process. Also use when the user says things like "let's release", "prepare a release", "make a new version", or "we're ready to ship".
---

# Release

Release flow: determine version → apply bump → pre-release checks → commit/push → tag → verify.

## 1. Determine version

```bash
git tag --list 'v*' --sort=-v:refname | head -5
git log <last_tag>..HEAD --format="%s%n%b---" --no-merges
```

Classify: **patch** (bug fixes), **minor** (new features), **major** (breaking changes). Confirm with user.

## 2. Apply version bump

Update version in all `package.json` files (root + 5 packages under `packages/*`).

## 3. Pre-release checks

```bash
bun run check-types && bun test && bun run build
bun dist/wallet-cli/index.js --help
bun dist/issuer-cli/index.js --help
```

## 4. Commit and push

**Before tagging, push all pending commits including the version bumps:**

```bash
git add -A && git commit -m "chore: bump to v<version>" && git push
```

## 5. Tag and push

```bash
git tag v<version> && git push origin v<version>
```

## 6. Verify

```bash
gh run list --limit 1
gh release view v<version>
```

Release workflow publishes `@vidos-id/*` packages to GitHub Packages and attaches `wallet-cli.js` and `issuer-cli.js` to the release.
