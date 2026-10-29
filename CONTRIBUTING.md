# Contributing

Thanks for your interest in the IT Service Agent Demo. This is a small portfolio and reference project, so contributions are kept simple.

## Ground rules

* **Synthetic data only.** Never add real names, hosts, tickets, keys, or tokens. Use `example.test` addresses and obviously fake secrets.
* **Keep it offline and dependency-free.** The agent uses only the Python standard library; `pytest` is the only test dependency. Tests must not need network access or API keys.
* **Do not weaken a control to make a test pass.** If a control changes on purpose, update the tests and `THREAT_MODEL.md` in the same pull request and explain why.
* **Be honest in the docs.** Do not claim certification, compliance, or live-model results the repository does not demonstrate.

## Set up and test

```bash
git clone https://github.com/lonnie-thomas/it-service-agent-demo.git
cd it-service-agent-demo
make install
make test        # expect all tests to pass
make demo        # optional end-to-end walk-through
```

If you change a runbook in `runbooks/`, review the change carefully and then re-pin the hashes with `make manifest`. The agent refuses to load runbooks that do not match `runbooks/MANIFEST.sha256`.

## Pull requests

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Create a branch, make a focused change, and add or update tests.
3. Run `make test` and confirm it passes. If you touched anything the companion [agent-security-test-kit](https://github.com/lonnie-thomas/agent-security-test-kit) exercises, run its suite against your branch too.
4. Write a clear commit message (for example `fix(approvals): reject approval with future issue time`) and describe what changed and why in the pull request.

By contributing, you agree that your contribution is licensed under the MIT license in [LICENSE](LICENSE).

For security problems, please do not open a public issue; see [SECURITY.md](SECURITY.md).
