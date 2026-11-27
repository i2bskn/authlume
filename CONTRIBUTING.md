# Contributing

Thank you for considering a contribution. This page explains how to build and test the module and what a change needs before it can be merged.

Report a security problem privately as described in [SECURITY.md](SECURITY.md), not in an issue or pull request.

## Before you start

Open an issue first for anything larger than a small fix. Authentication code is easier to review when the behavior is agreed before the code is written, and some requests belong in the application rather than in this module. The guides list what each package leaves to the application.

## Build and test

You need Go 1.26 or later. The module has no code generation step and no service to start.

```sh
go build ./...
go vet ./...
go test -race ./...
gofmt -l .
```

`gofmt -l .` must print nothing. The tests of the `password` package run real Argon2id derivations and take about half a minute with the race detector.

## What a change needs

- **Tests that fail without the change.** For a fix, add a test that reproduces the problem. For a new check, add a test for the accepted case and for each rejected case.
- **No change to default behavior without discussion.** A stricter or looser behavior is normally added as an option, and the default stays as it is.
- **Documentation.** Update the doc comments, and the guide under `docs/src/content/docs/` when the change is visible to users. State what the application must do, not only what the package does.
- **A custom store keeps working, or the break is stated.** Changing a store interface breaks every application that implements it. Say so in the pull request description.
- **No new dependency without discussion.** Several packages depend on the standard library only, and that is intended.

## Documentation site

The site is built with Astro and Starlight from the `docs/` directory.

```sh
cd docs
pnpm install
pnpm dev
```

`pnpm build` writes the site to `docs/dist/`.

## Commit messages

Write one sentence in the imperative that says what the change does, for example "Add an opt-in totp option that accepts only the current period".

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
