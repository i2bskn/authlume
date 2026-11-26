# Security policy

## Reporting a vulnerability

Report a suspected vulnerability privately through GitHub: open the [Security tab](https://github.com/i2bskn/authlume/security) of this repository and choose **Report a vulnerability**. Do not open a public issue or pull request for it.

Include what you can of the following:

- the package and the commit you tested
- what an attacker can do, and what they need to do it
- steps or code that reproduce the problem

You will get a reply in the private report. A fix is developed there and published together with an advisory.

## Supported versions

Authlume has no tagged release yet. Fixes are made on the `main` branch only, so upgrade to the latest commit to receive them.

## Scope

In scope are the packages of this module: `password`, `session`, `totp`, `webauthn`, `oidc` and `mcpoauth`.

The programs under `examples/` are demonstrations. They keep their state in memory and use deliberately simple limits. A weakness that exists only because an example is used as a production service is not a vulnerability of the module, but a report that an example teaches an unsafe pattern is welcome as a regular issue.

Each package leaves some duties to the application, such as rate limits, account recovery and the consent screen. The guides list them. A missing control that the documentation assigns to the application is not a vulnerability of the module. Unclear or missing documentation of such a duty is worth an issue.
