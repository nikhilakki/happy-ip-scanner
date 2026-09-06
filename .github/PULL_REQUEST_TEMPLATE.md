## Summary

<!-- What does this change and why? A sentence or two is enough. -->

## Related issue

<!-- Closes #123, or "none" -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor or cleanup (no behaviour change)
- [ ] Documentation
- [ ] CI or tooling
- [ ] Other (explain in the summary)

## Testing

<!-- How did you verify this? Note which OS you tested on (macOS, Linux, Windows) and whether you exercised the GUI, the CLI, or both. -->

## Checklist

- [ ] `cargo fmt --all --check` passes locally
- [ ] `cargo clippy --all-targets -- -D warnings` passes locally
- [ ] `cargo test` passes locally
- [ ] Any new tests bind only to 127.0.0.1 and never touch a real network
- [ ] README.md and CHANGELOG.md updated if the change is user-visible
- [ ] PR title follows Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `style:`, `chore:`, `refactor:`, `test:`)
