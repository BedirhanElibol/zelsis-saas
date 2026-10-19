# Monthly rule refresh

Run once a month. Each step ends in either "no change" or a commit with a changelog entry.

1. Read the release notes since last month for Next.js, React, Supabase (supabase-js, auth, RLS docs), Stripe API and Node.js LTS.
2. For each changed default or deprecated API, search `lib/rules` for rules that depend on it. Narrow or remove rules the release made wrong; add a rule only with a fixture in `tests/rules/cases.ts`.
3. Check the false-positive marks from the dashboard for the month. Any rule marked more than once gets a look.
4. Run `npm test`, then `npm run benchmark` twice and `npm run benchmark -- --check`. No new false positives on the corpus.
5. Run `npm run audit:rules` so `data/rules-version.generated.json` moves, and add a changelog entry in `data/changelog.ts`.
