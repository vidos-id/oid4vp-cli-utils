---
name: generate-release-notes
description: Generate the `.release_notes.md` file required before preparing a release. Use this skill whenever the user wants to prepare release notes, draft release notes, summarize changes for a release, or asks what should go into `.release_notes.md`.
---

# Generate Release Notes

This skill does not bump versions, tag, publish, or create releases.

Its only purpose is to generate `.release_notes.md` for the next release.

## Workflow

1. Determine release range

```bash
git tag --list 'v*' --sort=-v:refname
git log <last_tag>..HEAD --format="%s%n%b---" --no-merges
```

2. Review the actual shipped changes

- Inspect the commits since the last tag.
- Group them into highlights, features, fixes, and other notable changes.
- Exclude noise unless it affects users, operators, or integrators.

3. Write `.release_notes.md`

Use this structure:

```md
# Release v<version>

## Highlights

- ...

## New Features

- ...

## Bug Fixes

- ...

## Other Changes

- ...
```

Guidelines:

- Write for humans, not as a raw commit dump.
- Focus on user-visible behavior and integration-relevant changes.
- Keep bullets concise and specific.
- If a section has no meaningful entries, omit it instead of padding it.

4. Verify and save

- Ensure the file path is exactly `.release_notes.md` at repo root.
- Ensure the version header matches the intended release.

5. Commit and push the file before release preparation

The developer must commit and push `.release_notes.md` before running the release preparation workflow.

Example:

```bash
git add .release_notes.md
git commit -m "docs: add release notes for v<version>"
git push
```

## Important

- The release workflows require `.release_notes.md` to exist.
- After a successful release, CI deletes `.release_notes.md` from the default branch.
- That means every new release requires a freshly generated `.release_notes.md` file.
