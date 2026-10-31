/**
 * The GitHub Actions workflow shown to customers (dashboard, onboarding, /docs). One source so every copy
 * calls the real endpoint (/api/v1/gate-check) with the real auth (x-api-key) and inputs (repoUrl, ref, base).
 */
export interface GateWorkflowOptions {
  appUrl: string;
  projectName?: string;
  /** Shell lines run with $STATUS and $SCORE set; defaults to failing on a FAILED gate. */
  failCheck?: string;
}

export const DEFAULT_FAIL_CHECK = `if [ "$STATUS" = "FAILED" ]; then echo "::error::Zelsis gate FAILED (score $SCORE/100)"; exit 1; fi`;

export function buildGateWorkflow({ appUrl, projectName = 'your app', failCheck = DEFAULT_FAIL_CHECK }: GateWorkflowOptions): string {
  return `name: Zelsis Pre-Flight Release Gate

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  zelsis-gate:
    name: Zelsis Release Gate (${projectName})
    runs-on: ubuntu-latest
    steps:
      - name: Run Zelsis gate check
        env:
          # Create a key in Zelsis: Settings -> API keys. Required for private repositories.
          ZELSIS_API_KEY: \${{ secrets.ZELSIS_API_KEY }}
          # Lets Zelsis read a private repository for this run only.
          GH_READ_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          REF=""
          BASE=""
          if [ "\${{ github.event_name }}" = "pull_request" ]; then
            REF="\${{ github.event.pull_request.head.sha }}"
            BASE="\${{ github.event.pull_request.base.sha }}"
          fi

          FAIL_OPEN="\${{ vars.ZELSIS_FAIL_OPEN || 'false' }}"

          RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "${appUrl}/api/v1/gate-check" \\
            -H "Content-Type: application/json" \\
            -H "x-api-key: $ZELSIS_API_KEY" \\
            -d '{"repoUrl": "\${{ github.server_url }}/\${{ github.repository }}", "githubToken": "'$GH_READ_TOKEN'", "ref": "'$REF'", "base": "'$BASE'"}')

          HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
          BODY=$(echo "$RESPONSE" | sed '$d')

          if [ "$HTTP_CODE" -ge 400 ] && [ "$HTTP_CODE" -lt 500 ]; then
            echo "::error::Zelsis rejected the request (HTTP $HTTP_CODE): $(echo "$BODY" | jq -r '[.error // "see log"] + [.details[]? | .field + ": " + .message] | join("; ")'). Check the ZELSIS_API_KEY secret."
            exit 1
          fi

          if [ "$HTTP_CODE" -ge 500 ] || [ -z "$BODY" ] || ! echo "$BODY" | jq -e . >/dev/null 2>&1; then
            echo "Zelsis API unreachable or returned an invalid response."
            if [ "$FAIL_OPEN" = "true" ]; then
              echo "Fail-open is enabled: passing the gate."
              echo '{"gateStatus": "PASSED", "readinessScore": 100}' > zelsis-report.json
              exit 0
            fi
            exit 1
          fi

          echo "$BODY" > zelsis-report.json
          STATUS=$(jq -r '.gateStatus // "ERROR"' zelsis-report.json)
          SCORE=$(jq -r '.readinessScore // 0' zelsis-report.json)
          echo "Gate: $STATUS, score: $SCORE/100" >> $GITHUB_STEP_SUMMARY
          # Shows each finding on its line in the pull request diff
          jq -r '.annotations[]? // empty' zelsis-report.json
          ${failCheck}

      - name: Upload gate report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: zelsis-release-report
          path: zelsis-report.json
`;
}

/** The composite action in this repository (actions/gate): the same call as buildGateWorkflow in one step. */
export const GATE_ACTION_REF = 'BedirhanElibol/zelsis-saas/actions/gate@main';

export function buildGateActionWorkflow(): string {
  return `name: Zelsis Release Gate

on:
  pull_request:
    branches: [main, master, develop]

permissions:
  contents: read

jobs:
  zelsis:
    runs-on: ubuntu-latest
    steps:
      - uses: ${GATE_ACTION_REF}
        with:
          # Settings -> API keys in Zelsis. Required for private repositories.
          api-key: \${{ secrets.ZELSIS_API_KEY }}
`;
}
