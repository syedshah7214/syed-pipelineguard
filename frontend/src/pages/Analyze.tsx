import { FileCode2, FlaskConical, GitBranch, Play, Upload, X } from "lucide-react";
import { useRef, useState } from "react";
import { useToast } from "../components/Toasts";
import { Card, CardHead, ErrorState, PageHeader, Segmented, Select, Skeleton } from "../components/ui";
import { api } from "../lib/api";
import { titleCase } from "../lib/format";
import { useAsync } from "../lib/hooks";
import { usePrefs, type Prefs } from "../lib/prefs";
import { navigate } from "../lib/router";
import { useStatus } from "../lib/status";
import type { AuditResult, WorkflowFile } from "../lib/types";

type Mode = "sample" | "paste" | "upload" | "repo";
const MAX = 512 * 1000;
const PLACEHOLDER = `name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "\${{ github.event.pull_request.title }}"`;

export default function Analyze() {
  const { prefs, set } = usePrefs();
  const { bump } = useStatus();
  const toast = useToast();
  const samples = useAsync((sig) => api.samples(sig), []);
  const [mode, setMode] = useState<Mode>("sample");
  const [sample, setSample] = useState("pwn-request-bot");
  const [text, setText] = useState("");
  const [files, setFiles] = useState<WorkflowFile[]>([]);
  const [repo, setRepo] = useState("");
  const [ref, setRef] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const onFiles = (list: FileList | null) => {
    setError(null);
    if (!list) return;
    const picked = Array.from(list).filter((f) => /\.ya?ml$/i.test(f.name));
    if (!picked.length) { setError("Choose .yml or .yaml workflow files."); return; }
    const big = picked.find((f) => f.size > MAX);
    if (big) { setError(`${big.name} is larger than 500 KB.`); return; }
    Promise.all(picked.map((f) => f.text().then((content) => ({ path: `.github/workflows/${f.name}`, content }))))
      .then((read) => setFiles((cur) => [...cur.filter((c) => !read.some((r) => r.path === c.path)), ...read].slice(0, 50)))
      .catch(() => setError("Could not read the files."));
  };

  const finish = (res: AuditResult, label: string) => {
    toast.push({ tone: res.report.decision === "PASS" ? "success" : res.report.decision === "WARN" ? "warn" : "error", title: `${label}: ${res.report.decision} · ${res.report.score}/100`, body: res.report.reasons[0] });
    bump();
    navigate(`/report?id=${res.id}`);
  };

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      if (mode === "repo") {
        if (!repo.trim()) throw new Error("Enter a public repository, e.g. owner/repo.");
        const res = await api.scanRepo(repo.trim(), ref.trim() || null, prefs.failOn);
        finish(res, res.name);
        return;
      }
      let body: WorkflowFile[];
      let label = name.trim();
      if (mode === "sample") {
        const s = await api.sample(sample);
        body = s.files; label ||= titleCase(sample);
      } else if (mode === "paste") {
        if (!text.trim()) throw new Error("Paste a workflow YAML first.");
        body = [{ path: ".github/workflows/pasted.yml", content: text }]; label ||= "Pasted workflow";
      } else {
        if (!files.length) throw new Error("Choose one or more workflow files first.");
        body = files; label ||= files.length === 1 ? files[0].path.split("/").pop()! : `${files.length} workflows`;
      }
      const res = await api.analyze({ files: body, name: label, source: mode === "sample" ? "sample" : "upload", fail_on: prefs.failOn });
      finish(res, label);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack-lg">
      <PageHeader eyebrow="Audit" title="Audit GitHub Actions workflows"
        description={<>Point PipelineGuard at the files in <code>.github/workflows/</code>. The YAML is parsed statically by your local API — nothing is executed — and every audit is saved to your history.</>} />
      <section className="grid grid--lab">
        <Card>
          <CardHead icon={<FlaskConical size={17} />} title="Gate policy" sub="Saved as your default" />
          <div className="form">
            <Select label="Fail the gate on findings at or above" value={prefs.failOn} onChange={(v) => set("failOn", v as Prefs["failOn"])}
              options={["critical", "high", "medium", "low"].map((s) => ({ value: s, label: s }))} />
            {mode !== "repo" && <label className="field"><span>Audit name (optional)</span><input value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder="e.g. PR #42 — new release job" /></label>}
            <div className="legend">
              <p><b className="pill pill--fail pill--sm">FAIL</b> a finding at/above the threshold, or a file that does not parse</p>
              <p><b className="pill pill--warn pill--sm">WARN</b> medium findings to review</p>
              <p><b className="pill pill--pass pill--sm">PASS</b> only low-severity hygiene hints</p>
            </div>
            <p className="muted small">Score: 100 − 25 per critical, 12 per high, 5 per medium, 2 per low (per file, averaged). A ≥ 90 · B ≥ 80 · C ≥ 65 · D ≥ 50 · F.</p>
          </div>
        </Card>

        <Card>
          <CardHead icon={<FileCode2 size={17} />} title="Workflows" actions={<Segmented label="Input type" value={mode} onChange={setMode}
            options={[{ value: "sample", label: "Samples" }, { value: "paste", label: "Paste YAML" }, { value: "upload", label: "Upload" }, { value: "repo", label: "Public repo" }]} />} />
          {mode === "sample" && (samples.error ? <ErrorState error={samples.error} onRetry={samples.reload} /> : !samples.data ? <Skeleton h={220} /> : (
            <div className="samplegrid" role="radiogroup" aria-label="Sample workflows">
              {samples.data.map((s) => (
                <button key={s.name} role="radio" aria-checked={sample === s.name} className={`samplecard ${sample === s.name ? "on" : ""}`} onClick={() => setSample(s.name)}>
                  <b>{titleCase(s.name)}</b><span className="muted small">{s.description}</span><span className="mono small">{s.files} workflow file{s.files === 1 ? "" : "s"}</span>
                </button>
              ))}
              <p className="badge badge--demo">Samples are hand-written to show real attack patterns; they are not from a real repository.</p>
            </div>
          ))}
          {mode === "paste" && (
            <label className="field"><span>Workflow YAML</span>
              <textarea className="codearea" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder={PLACEHOLDER} />
            </label>
          )}
          {mode === "upload" && (
            <div className="dropzone" onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); onFiles(e.dataTransfer.files); }}>
              <Upload size={26} aria-hidden="true" />
              <p>{files.length ? <b>{files.length} file{files.length === 1 ? "" : "s"} ready</b> : "Drop workflow .yml files here"}</p>
              {files.length > 0 && <div className="filechips">{files.map((f) => (
                <span key={f.path} className="chip">{f.path.split("/").pop()}<button aria-label={`Remove ${f.path}`} onClick={() => setFiles((c) => c.filter((x) => x.path !== f.path))}><X size={12} /></button></span>
              ))}</div>}
              <button className="btn" onClick={() => fileRef.current?.click()}>Choose files</button>
              <input ref={fileRef} type="file" accept=".yml,.yaml" multiple hidden onChange={(e) => onFiles(e.target.files)} />
              <p className="muted small">Read in your browser and sent only to your PipelineGuard API. Up to 50 files, 500 KB each.</p>
            </div>
          )}
          {mode === "repo" && (
            <div className="form">
              <label className="field"><span>Public GitHub repository</span>
                <div className="input input--lg"><GitBranch size={16} aria-hidden="true" /><input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="owner/repo or https://github.com/owner/repo" onKeyDown={(e) => { if (e.key === "Enter") void run(); }} /></div>
              </label>
              <label className="field"><span>Branch, tag or SHA (optional)</span><input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="default branch" /></label>
              <p className="muted small">Read-only: the API downloads <code>.github/workflows/*.yml</code> through the public GitHub REST API. No token is needed (60 requests/hour); private repos are not supported.</p>
            </div>
          )}
          {error && <p className="formerror" role="alert">{error}</p>}
          <button className="btn btn--primary btn--block" onClick={() => void run()} disabled={busy}><Play size={15} />{busy ? "Auditing…" : mode === "repo" ? "Scan repository" : "Run PipelineGuard"}</button>
        </Card>
      </section>
    </div>
  );
}
