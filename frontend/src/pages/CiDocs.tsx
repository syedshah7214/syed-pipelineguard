import { BookOpen, ExternalLink, ShieldCheck, Terminal, Workflow } from "lucide-react";
import { Card, CardHead, JsonBlock, PageHeader } from "../components/ui";
import { API_BASE } from "../lib/api";

const ACTION = `# .github/workflows/pipelineguard.yml
name: pipelineguard
on:
  pull_request:
    paths: [".github/workflows/**"]
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - id: guard
        uses: syedshah7214/syed-pipelineguard@main
        with:
          path: .github/workflows
          fail-on: high
          sarif-file: pipelineguard.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pipelineguard.sarif`;

export default function CiDocs() {
  return (
    <div className="stack-lg">
      <PageHeader eyebrow="Integrate" title="CI Integration" description="The same engine powers the CLI, the composite GitHub Action and this dashboard. Run it on every pull request that touches a workflow."
        actions={<a className="btn" href={`${API_BASE}/docs`} target="_blank" rel="noreferrer">API docs <ExternalLink size={13} /></a>} />
      <section className="grid grid--2">
        <Card>
          <CardHead icon={<Terminal size={17} />} title="Command line" />
          <JsonBlock label="shell" value={`cd backend\npython -m pipelineguard ../.github/workflows --fail-on high\npython -m pipelineguard ../.github/workflows --format sarif --output pg.sarif\npython -m pipelineguard ../.github/workflows --write-fixes fixed/\npython -m pipelineguard ci.yml --format markdown > comment.md`} />
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Exit code</th><th>Meaning</th></tr></thead>
            <tbody><tr><td className="mono">0</td><td>PASS or WARN — merge may continue</td></tr><tr><td className="mono">1</td><td>FAIL — stop the pipeline</td></tr><tr><td className="mono">2</td><td>Invalid input (file missing or not a workflow)</td></tr></tbody>
          </table></div>
        </Card>
        <Card>
          <CardHead icon={<Workflow size={17} />} title="GitHub Action + code scanning" sub="action.yml in the repository root" />
          <JsonBlock label="yaml" value={ACTION} />
          <p className="muted small">The action writes a Markdown report to the job summary, adds inline annotations for critical/high findings, and fails the job on FAIL. With the SARIF upload, findings also appear in the repository's Security → Code scanning tab.</p>
        </Card>
      </section>
      <section className="grid grid--2">
        <Card>
          <CardHead icon={<ShieldCheck size={17} />} title="What is checked" />
          <ul className="reasons">
            <li><b>Security</b> — pwn requests on pull_request_target, script injection from PR titles/branches, hard-coded keys, secrets in logs, write-all tokens, self-hosted runners on PRs, curl | bash.</li>
            <li><b>Supply chain</b> — third-party actions not pinned to a commit SHA, mutable container images, archived actions, <code>secrets: inherit</code>.</li>
            <li><b>Reliability</b> — deprecated action majors, set-output, quality gates hidden by continue-on-error, npm install.</li>
            <li><b>Performance</b> — no dependency cache, no timeout, no concurrency cancel, full clones, 10× macOS minutes.</li>
          </ul>
        </Card>
        <Card>
          <CardHead icon={<BookOpen size={17} />} title="How this repository tests itself" />
          <ul className="reasons">
            <li>pytest unit + API tests with a coverage gate, ruff, ESLint and a TypeScript production build.</li>
            <li>Dogfooding: PipelineGuard audits <b>its own</b> workflows through <code>uses: ./</code> and must PASS.</li>
            <li>The vulnerable samples must FAIL, and every auto-fixed sample must still be valid YAML.</li>
            <li>gitleaks secret scan and dependency audits (pip-audit, npm audit).</li>
          </ul>
        </Card>
      </section>
    </div>
  );
}
