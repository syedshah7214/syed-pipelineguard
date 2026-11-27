import { ArrowRight, Boxes, Check, Copy, Download, FileCode2, ShieldAlert, Sparkles, Wand2 } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { downloadText, titleCase } from "../lib/format";
import type { Category, Finding, Fix, Report, Severity } from "../lib/types";
import { Donut } from "./charts";
import { useToast } from "./Toasts";
import { Card, CardHead, DECISION_TEXT, DecisionPill, EmptyState, Expandable, JsonBlock, Segmented, SevBadge, Stat } from "./ui";

const SEVS: Severity[] = ["critical", "high", "medium", "low"];
const CATS = ["all", "security", "supply-chain", "reliability", "performance"] as const;
const GRADE_TONE: Record<string, string> = { A: "var(--green)", B: "var(--cyan)", C: "var(--amber)", D: "var(--amber)", F: "var(--red)" };

export function ScoreRing({ score, grade, label, size = 150 }: { score: number; grade: string; label: string; size?: number }) {
  return (
    <div className="scorering">
      <Donut value={score / 100} size={size} stroke={12} tone={GRADE_TONE[grade] ?? "var(--cyan)"} label={<>{score}<small>/100</small></>} sub={`grade ${grade}`} />
      <span className="scorering__label">{label}</span>
    </div>
  );
}

function where(f: Finding) {
  return `${f.file}:${f.line}`;
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <Expandable
      title={<><SevBadge s={f.severity} /><span className="mono small">{f.rule_id}</span> {f.title}{f.autofix && <span className="fixtag"><Wand2 size={11} /> auto-fix</span>}</>}
      meta={<code>{where(f)}{f.job ? ` · ${f.job}` : ""}</code>}>
      <dl className="kv kv--stack">
        <div><dt>What we found</dt><dd>{f.detail}</dd></div>
        {f.step && <div><dt>Step</dt><dd><code>{f.step}</code></dd></div>}
        <div><dt>How to fix</dt><dd>{f.remediation}</dd></div>
        <div><dt>Reference</dt><dd><a className="link" href={f.reference} target="_blank" rel="noreferrer">{f.reference.replace(/^https:\/\//, "").slice(0, 80)}</a> · {f.category}</dd></div>
      </dl>
    </Expandable>
  );
}

export function DiffView({ diff }: { diff: string }) {
  const lines = diff.split("\n").filter((l, i, a) => !(i === a.length - 1 && l === ""));
  return (
    <pre className="diff" aria-label="Unified diff of the auto-fix">
      {lines.map((l, i) => {
        const cls = l.startsWith("+++") || l.startsWith("---") ? "diff__file" : l.startsWith("@@") ? "diff__hunk" : l.startsWith("+") ? "diff__add" : l.startsWith("-") ? "diff__del" : "";
        return <span key={i} className={`diff__line ${cls}`}>{l || " "}{"\n"}</span>;
      })}
    </pre>
  );
}

function FixCard({ fx }: { fx: Fix }) {
  const toast = useToast();
  const [view, setView] = useState<"diff" | "changes">("diff");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(fx.fixed);
      toast.push({ tone: "success", title: "Fixed workflow copied", body: fx.path });
    } catch {
      toast.push({ tone: "error", title: "Clipboard blocked", body: "Use Download instead." });
    }
  };
  return (
    <Card className="fixcard">
      <CardHead icon={<Wand2 size={17} />} title={<span className="mono">{fx.path}</span>}
        sub={<>score <b>{fx.score_before}</b> <ArrowRight size={12} /> <b className="good">{fx.score_after}</b> · {fx.applied.length} edits · comments and formatting kept</>}
        actions={<div className="chips">
          <Segmented label="View" value={view} onChange={setView} options={[{ value: "diff", label: "Diff" }, { value: "changes", label: "Changes" }]} />
          <button className="btn" onClick={copy}><Copy size={14} /> Copy</button>
          <button className="btn btn--primary" onClick={() => downloadText(fx.path.split("/").pop() ?? "workflow.yml", fx.fixed, "text/yaml")}><Download size={14} /> Fixed YAML</button>
        </div>} />
      {view === "diff" ? <DiffView diff={fx.diff} /> : (
        <ul className="fixlist">
          {fx.applied.map((a, i) => <li key={i}><span className="mono small">{a.rule_id}</span><span className="muted small">L{a.line}</span><span>{a.change}</span></li>)}
        </ul>
      )}
    </Card>
  );
}

export function ReportView({ report, id, name }: { report: Report; id: number | null; name: string }) {
  const toast = useToast();
  const [cat, setCat] = useState<(typeof CATS)[number]>("all");
  const [sev, setSev] = useState<"all" | Severity>("all");
  const [copied, setCopied] = useState(false);
  const findings = useMemo(() => report.findings.filter((f) => (cat === "all" || f.category === cat) && (sev === "all" || f.severity === sev)), [report, cat, sev]);
  const t = report.totals;
  const s = report.findings_by_severity;
  const gain = report.score_after_fixes - report.score;

  const copyComment = async () => {
    if (!id) return;
    try {
      const md = await api.markdown(id);
      await navigator.clipboard.writeText(md);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
      toast.push({ tone: "success", title: "PR comment copied", body: "Paste it into a pull request or issue." });
    } catch (e) {
      toast.push({ tone: "error", title: "Could not copy", body: (e as Error).message });
    }
  };
  const getSarif = async () => {
    if (!id) return;
    try {
      downloadText(`pipelineguard-${id}.sarif`, JSON.stringify(await api.sarif(id), null, 2));
    } catch (e) {
      toast.push({ tone: "error", title: "Could not export SARIF", body: (e as Error).message });
    }
  };

  return (
    <div className="stack-lg">
      <section className={`card verdictcard verdictcard--${report.decision.toLowerCase()}`} aria-live="polite">
        <div className="verdictcard__main">
          <p className="eyebrow">Gate decision · {name}</p>
          <div className="verdictcard__row">
            <DecisionPill d={report.decision} size="lg" />
            <span className="verdictcard__text">{DECISION_TEXT[report.decision]}</span>
          </div>
          <ul className="reasons">{report.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
          <div className="verdictcard__actions verdictcard__actions--row">
            {id && <button className="btn" onClick={copyComment}>{copied ? <Check size={14} /> : <Copy size={14} />} PR comment</button>}
            {id && <button className="btn" onClick={getSarif}><Download size={14} /> SARIF</button>}
            <button className="btn" onClick={() => downloadText(`pipelineguard-report-${id ?? "draft"}.json`, JSON.stringify(report, null, 2))}><Download size={14} /> JSON</button>
            <span className="muted small">fail on ≥ <b>{report.options.fail_on}</b> · {report.rules_evaluated} rules</span>
          </div>
        </div>
        <div className="scorepair">
          <ScoreRing score={report.score} grade={report.grade} label="Now" />
          {report.fixes.length > 0 && <>
            <div className="scorepair__arrow"><Sparkles size={16} /><span>+{gain}</span><small>auto-fix</small></div>
            <ScoreRing score={report.score_after_fixes} grade={report.grade_after_fixes} label="After safe fixes" />
          </>}
        </div>
      </section>

      <section className="grid grid--4">
        <Card>
          <Stat label="Findings" value={report.findings.length} tone={s.critical + s.high ? "bad" : report.findings.length ? "warn" : "ok"} hint={`${report.autofixable} auto-fixable`} />
          <div className="sevcounts">{SEVS.map((x) => <span key={x} className={`sevtag sevtag--${x}`}>{s[x]} {x}</span>)}</div>
        </Card>
        <Card><Stat label="Workflows · jobs · steps" value={`${t.files} · ${t.jobs} · ${t.steps}`} hint="parsed statically, nothing executed" /></Card>
        <Card><Stat label="Third-party actions SHA-pinned" value={t.third_party_actions ? `${t.third_party_pinned}/${t.third_party_actions}` : "none used"} tone={t.third_party_actions && t.third_party_pinned < t.third_party_actions ? "bad" : "ok"} hint={`${t.actions} distinct actions`} /></Card>
        <Card>
          <Stat label="By category" value={Object.keys(report.findings_by_category).length || "—"} hint="categories with findings" />
          <div className="sevcounts">{(Object.entries(report.findings_by_category) as [Category, number][]).map(([c, n]) => <span key={c} className="sevtag sevtag--cat">{n} {c}</span>)}</div>
        </Card>
      </section>

      <Card>
        <CardHead icon={<ShieldAlert size={17} />} title="Findings" sub={`${findings.length} of ${report.findings.length} · sorted by severity, then line`}
          actions={<div className="filters">
            <Segmented label="Severity" value={sev} onChange={setSev} options={[{ value: "all", label: "All" }, ...SEVS.map((x) => ({ value: x, label: titleCase(x) }))]} />
            <Segmented label="Category" value={cat} onChange={setCat} options={CATS.map((x) => ({ value: x, label: x === "all" ? "All" : titleCase(x) }))} />
          </div>} />
        {findings.length === 0 ? <EmptyState title={report.findings.length ? "Nothing matches this filter" : "No findings"}>{report.findings.length ? null : "Every rule passed."}</EmptyState>
          : <div className="stack-sm">{findings.map((f, i) => <FindingRow key={`${f.rule_id}-${f.file}-${f.line}-${i}`} f={f} />)}</div>}
      </Card>

      {report.fixes.length > 0 && (
        <section className="stack">
          <div className="sectionhead"><Wand2 size={18} /><h2>Auto-fix preview</h2><span className="muted small">Line edits on your original YAML — re-parsed and re-audited before they are shown.</span></div>
          {report.fixes.map((fx) => <FixCard key={fx.path} fx={fx} />)}
        </section>
      )}

      <section className="grid grid--split">
        <Card>
          <CardHead icon={<FileCode2 size={17} />} title="Workflow files" />
          <div className="table-wrap"><table className="table">
            <thead><tr><th>File</th><th>Triggers</th><th>Jobs</th><th>Findings</th><th>Score</th></tr></thead>
            <tbody>{report.files.map((f) => (
              <tr key={f.path}>
                <td className="mono small">{f.path}{f.error && <div className="bad small">{f.error}</div>}</td>
                <td className="small">{(f.triggers ?? []).join(", ") || "—"}</td>
                <td className="mono">{f.jobs ?? "—"}</td>
                <td className="mono">{f.findings ?? "—"}</td>
                <td className="mono"><span className={`grade grade--${f.grade}`}>{f.grade}</span> {f.score}{f.score_after !== undefined && f.score_after !== f.score && <span className="good"> → {f.score_after}</span>}</td>
              </tr>))}</tbody>
          </table></div>
        </Card>
        <Card>
          <CardHead icon={<Boxes size={17} />} title="Action inventory" sub="Every `uses:` reference, supply-chain view" />
          {report.inventory.length === 0 ? <p className="muted small">No marketplace actions used.</p> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Action</th><th>Ref</th><th>Owner</th><th>Pinned</th><th>Uses</th></tr></thead>
              <tbody>{report.inventory.map((a) => (
                <tr key={`${a.action}@${a.ref}`}>
                  <td className="mono small">{a.action}</td><td className="mono small">{a.ref ? (a.pinned ? `${a.ref.slice(0, 10)}…` : a.ref) : "—"}</td>
                  <td className="small">{a.github_owned ? "GitHub" : <span className="warnc">third-party</span>}</td>
                  <td>{a.pinned ? <span className="good small">SHA</span> : <span className={a.github_owned ? "muted small" : "bad small"}>tag</span>}</td>
                  <td className="mono">{a.uses}</td>
                </tr>))}</tbody>
            </table></div>
          )}
        </Card>
      </section>

      {id && <PrComment id={id} />}
    </div>
  );
}

function PrComment({ id }: { id: number }) {
  const [md, setMd] = useState<string | null>(null);
  return (
    <Expandable title="Pull-request comment preview (Markdown)" defaultOpen={false}>
      {md === null ? <button className="btn" onClick={() => api.markdown(id).then(setMd).catch((e) => setMd(`Could not load: ${(e as Error).message}`))}>Load preview</button>
        : <JsonBlock label="markdown" value={md} />}
    </Expandable>
  );
}
