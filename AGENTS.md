# Repository Instructions

This repository uses concise Conventional Commit messages.

Format:

```text
<type>(optional scope): <summary>
```

Allowed types:

- `feat`
- `fix`
- `docs`
- `test`
- `refactor`
- `chore`
- `ci`
- `build`
- `perf`

Rules:

- Use English.
- Use the imperative mood.
- Keep the summary under 72 characters.
- Do not add emojis.
- Do not mention AI, Codex, or generated changes.
- Prefer specific messages over generic ones.

## Pull Requests

Write clear and concise PR titles and descriptions in English.

PR title:

- Use a short descriptive title.
- Prefer Conventional Commit style when appropriate.
- Do not mention AI, Codex, or generated changes.

PR description:

Use this structure:

```md
## Summary

- Briefly describe what changed.

## Changes

- List the important code, test, or documentation changes.

## Testing

- List tests or checks that were run.

## Notes

- Mention risks, assumptions, or follow-up work if relevant.
```

Rules:

- Be specific.
- Avoid marketing language.
- Avoid overclaiming.
- Do not include unrelated details.

## Engineering Rules

- Be conservative.
- Do not make broad or unrelated changes.
- Before editing, inspect relevant files and summarize the intended change.
- Do not guess APIs, file paths, config keys, or test commands.
- If something is unclear, state the uncertainty and choose the safest minimal change.
- Prefer small, reviewable diffs.
- Preserve existing behavior unless the task explicitly asks to change it.
- Do not reformat unrelated files.
- Do not rename files, move files, or change public APIs unless required.
- Do not add new dependencies unless explicitly requested.
- Do not modify secrets, credentials, environment files, lock files, or generated files unless required.

## Verification Rules

- Run the most relevant tests or checks after editing.
- If tests cannot be run, explain why.
- Report exactly what was run and what passed or failed.
- Do not claim success without evidence.
- Mention remaining risks and assumptions.

## bd Issue Tracking

This project can use `bd` for local issue tracking.

Useful commands:

```bash
bd ready
bd show <id>
bd update <id> --status in_progress
bd close <id>
bd sync
```

In this fork, `.beads/` is configured as local-only in `.git/info/exclude`.
Do not assume bd issues are shared through git unless that policy is changed
intentionally.
