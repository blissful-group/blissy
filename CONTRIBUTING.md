# Contributing

Install the repository's managed tools with:

```sh
proto install
```

## Forking

Fork the public repository to your own GitHub account, then clone your fork locally and open pull requests back to the main repository.

## Changesets

Create a changeset with:

```sh
moon run :changeset
```

Version packages and changelogs with:

```sh
moon run :version
```

## Commit Messages

Commit messages should follow the Conventional Commits format:

```text
type(scope): short summary
```

Examples:

```text
feat(auth): add token refresh helper
fix(api): handle missing session cookie
docs: update setup instructions
```
