# Zelsis

Zelsis checks your pull requests for bugs your users would notice: a customer charged twice, a secret key shipped to the browser, a query that times out on real data, a checkout a keyboard cannot reach.

It is rule-based. Every finding comes from a written rule with a test, and no AI model reads your code. Only rules proven from the code can fail a check; everything else is a note you can read and ignore.

Try it without an account: paste a public repository at [zelsis.com](https://zelsis.com).

## Add it to a repository in one step

Save this as `.github/workflows/zelsis.yml`:

```yaml
name: Zelsis Release Gate

on:
  pull_request:
    branches: [main, master, develop]

permissions:
  contents: read

jobs:
  zelsis:
    runs-on: ubuntu-latest
    steps:
      - uses: BedirhanElibol/zelsis-saas/actions/gate@main
        with:
          # Settings -> API keys in Zelsis. Required for private repositories.
          api-key: ${{ secrets.ZELSIS_API_KEY }}
```

On a pull request the check sends the head and base commits, so it only fails on what the pull request introduces. Each finding shows up on its line in the "Files changed" tab. For production, pin the action to a commit SHA instead of `@main`.

Inputs: `api-key`, `app-url`, `fail-open`, `fail-on-failed`, `github-token`, `upload-report`. Outputs: `status` and `score`. The full guide is at [zelsis.com/docs/ci-gate](https://zelsis.com/docs/ci-gate).

## What it looks at

Payments (double charges, missing idempotency keys, webhooks that never revoke access), security (leaked keys, open database policies, missing auth checks), performance (N+1 queries, blocking migrations), privacy (cookie banners, session replay), and accessibility (checkouts a keyboard cannot use). The rules and their fixtures are in this repository.

## About this repository

This is the source of the Zelsis product. It is public so you can read how the scanner decides, and the code is proprietary: see [LICENSE](LICENSE). Found a false alarm or a miss? Open an issue; every false alarm we fix becomes a test that keeps it from coming back.

- Site: [zelsis.com](https://zelsis.com)
- Docs: [zelsis.com/docs](https://zelsis.com/docs)
- Changelog: [zelsis.com/changelog](https://zelsis.com/changelog)
