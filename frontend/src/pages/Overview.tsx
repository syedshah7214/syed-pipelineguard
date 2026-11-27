import { ArrowRight, History, Play, ScanSearch } from "lucide-react";
import { useState } from "react";
import { useToast } from "../components/Toasts";
import { Card, CardHead, DecisionPill, EmptyState, ErrorState, Pagination, Skeleton, Stat } from "../components/ui";
import { api } from "../lib/api";
import { ago, titleCase } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { usePrefs } from "../lib/prefs";
import { navigate } from "../lib/router";
import { useStatus } from "../lib/status";

const FLOW = [
  [".github/workflows/*.yml", "pushed in a pull request"], ["Parse", "YAML → jobs, steps, triggers"], ["24 rules", "security · supply chain · speed"],
  ["Gate + score", "PASS · WARN · FAIL, 0–100"], ["Fix", "auto-fix diff · SARIF · PR comment"],
];
const SAMPLES = ["pwn-request-bot", "self-hosted-leak", "legacy-node-ci", "slow-monorepo-ci", "hardened-release"];

export default function Overview() {
  const { tick, bump } = useStatus();
  const { prefs } = usePrefs();
  const toast = useToast();
  const [offset, setOffset] = useState(0);
  const [running, setRunning] = useState<string | null>(null);
  const stats = useAsync((sig) => api.stats(sig), [tick]);
  const hist = useAsync((sig) => api.analyses(8, offset, sig), [tick, offset]);
  const latest = hist.data?.items[0];

  const runSample = async (name: string) => {
    setRunning(name);
    try {
      const s = await api.sample(name);
      const r = await api.analyze({ files: s.files, name: titleCase(name), source: "sample", fail_on: prefs.failOn });
      bump();
      navigate(`/report?id=${r.id}`);
    } catch (e) {
      toast.push({ tone: "error", title: "Audit failed", body: (e as Error).message });
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="stack-lg">
      <section className="hero">
        <div className="hero__copy">
          <p className="eyebrow">GitHub Actions Security &amp; Performance Auditor</p>
          <h1>SYED <span className="grad">PipelineGuard</span></h1>
          <p className="hero__tagline">Your CI pipeline runs with your secrets. Audit it like production code.</p>
          <p className="hero__lede">PipelineGuard reads workflow YAML, finds <b>pwn requests</b>, <b>script injection</b>, <b>unpinned actions</b>, leaked secrets and slow, wasteful jobs — then scores the pipeline, gates the PR and writes a <b>safe auto-fix</b> you can review as a diff.</p>
          <div className="chips">
            <button className="btn btn--primary" onClick={() => navigate("/analyze")}><ScanSearch size={15} /> Audit workflows</button>
            <button className="btn" onClick={() => runSample("pwn-request-bot")} disabled={!!running}><Play size={15} />{running ? "Running…" : "Try the pwn-request sample"}</button>
          </div>
        </div>
        <Card className="flowcard">
          <CardHead title="How it works" sub="Static analysis — nothing is executed" />
          <ol className="vflow">
            {FLOW.map(([a, b], i) => <li key={a} className={i === 3 ? "vflow__gate" : ""}><span className="vflow__n">{i + 1}</span><span><b>{a}</b><small className="mono">{b}</small></span></li>)}
          </ol>
        </Card>
      </section>

      <section className="grid grid--4" aria-label="History statistics">
        {!stats.data ? Array.from({ length: 4 }, (_, i) => <Card key={i}><Skeleton h={50} /></Card>) : <>
          <Card><Stat label="Audits run" value={stats.data.audits} hint={`${stats.data.pass} pass · ${stats.data.warn} warn · ${stats.data.fail} fail`} /></Card>
          <Card><Stat label="Workflow files scanned" value={stats.data.workflows_scanned} hint="across all audits in this history" /></Card>
          <Card><Stat label="Critical + high findings" value={stats.data.critical_findings + stats.data.high_findings} tone={stats.data.critical_findings ? "bad" : undefined} hint="caught before merge" /></Card>
          <Card><Stat label="Average score" value={stats.data.avg_score === null ? "—" : <>{stats.data.avg_score}<span className="good small"> → {stats.data.avg_score_after_fixes}</span></>} tone="warn" hint="now → after auto-fix" /></Card>
        </>}
      </section>
      {stats.error && <ErrorState error={stats.error} onRetry={stats.reload} />}

      <section className="grid grid--split">
        <Card>
          <CardHead icon={<History size={17} />} title="Audit history" sub="Stored locally by your PipelineGuard API" />
          {hist.error ? <ErrorState error={hist.error} onRetry={hist.reload} /> : !hist.data ? <Skeleton h={240} /> : hist.data.total === 0 ? (
            <EmptyState title="No audits yet">Run a sample, paste a workflow or scan a public repo.</EmptyState>
          ) : (
            <>
              <div className="table-wrap"><table className="table table--rows">
                <thead><tr><th>#</th><th>Audit</th><th>Decision</th><th>Score</th><th>Crit/High</th><th>Files</th><th>When</th></tr></thead>
                <tbody>{hist.data.items.map((a) => (
                  <tr key={a.id} className="clickable" tabIndex={0} onClick={() => navigate(`/report?id=${a.id}`)} onKeyDown={(e) => { if (e.key === "Enter") navigate(`/report?id=${a.id}`); }}>
                    <td className="mono muted">{a.id}</td><td>{a.name} <span className="srcdot srcdot--demo">{a.source}</span></td>
                    <td><DecisionPill d={a.decision} /></td>
                    <td className="mono"><span className={`grade grade--${a.grade}`}>{a.grade}</span> {a.score}{a.score_after > a.score && <span className="good"> → {a.score_after}</span>}</td>
                    <td className={`mono ${a.critical + a.high ? "bad" : ""}`}>{a.critical}/{a.high}</td><td className="mono muted">{a.files}</td><td className="muted small">{ago(a.created_at)}</td>
                  </tr>))}</tbody>
              </table></div>
              <Pagination total={hist.data.total} limit={hist.data.limit} offset={hist.data.offset} onChange={setOffset} />
            </>
          )}
        </Card>
        <div className="stack">
          <Card>
            <CardHead title="Latest decision" />
            {!latest ? <p className="muted small">Nothing audited yet.</p> : (
              <div className="latest">
                <DecisionPill d={latest.decision} size="lg" />
                <p><b>{latest.name}</b><br /><span className="muted small">score {latest.score} (grade {latest.grade}) · {latest.critical} critical · {latest.high} high · {ago(latest.created_at)}</span></p>
                <a className="link" href={`#/report?id=${latest.id}`}>Open report <ArrowRight size={13} /></a>
              </div>
            )}
          </Card>
          <Card>
            <CardHead title="Quick samples" sub="Hand-written attack patterns" />
            <div className="stack-sm">
              {SAMPLES.map((s) => (
                <button key={s} className="samplerow" onClick={() => runSample(s)} disabled={!!running}><Play size={13} />{titleCase(s)}{running === s && <span className="muted small"> running…</span>}</button>
              ))}
            </div>
          </Card>
        </div>
      </section>
    </div>
  );
}
