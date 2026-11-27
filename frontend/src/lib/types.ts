export type Decision = "PASS" | "WARN" | "FAIL";
export type Severity = "critical" | "high" | "medium" | "low";
export type Category = "security" | "supply-chain" | "reliability" | "performance";

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  category: Category;
  file: string;
  line: number;
  job: string | null;
  step: string | null;
  detail: string;
  remediation: string;
  reference: string;
  autofix: boolean;
}

export interface FileRow {
  path: string;
  name?: string | null;
  triggers?: string[];
  jobs?: number;
  steps?: number;
  findings?: number;
  score: number;
  grade: string;
  score_after?: number;
  error: string | null;
}

export interface Fix {
  path: string;
  fixed: string;
  diff: string;
  valid: boolean;
  applied: { rule_id: string; line: number; change: string }[];
  score_before: number;
  score_after: number;
  findings_after: number;
}

export interface ActionUse { action: string; ref: string | null; pinned: boolean; github_owned: boolean; uses: number }

export interface Report {
  tool_version: string;
  decision: Decision;
  reasons: string[];
  score: number;
  grade: string;
  score_after_fixes: number;
  grade_after_fixes: string;
  files: FileRow[];
  findings: Finding[];
  findings_by_severity: Record<Severity, number>;
  findings_by_category: Partial<Record<Category, number>>;
  autofixable: number;
  fixes: Fix[];
  inventory: ActionUse[];
  totals: { files: number; jobs: number; steps: number; actions: number; third_party_actions: number; third_party_pinned: number };
  options: { fail_on: Severity; autofix: boolean };
  rules_evaluated: number;
}

export interface AuditSummary {
  id: number;
  name: string;
  source: "sample" | "upload" | "repo" | "ci";
  decision: Decision;
  score: number;
  grade: string;
  score_after: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  files: number;
  created_at: string;
}
/** kept for components shared with the other SYED dashboards */
export type AnalysisSummary = AuditSummary;

export interface Page<T> { total: number; limit: number; offset: number; items: T[] }
export interface WorkflowFile { path: string; content: string }
export interface Sample { name: string; description: string; files: number }
export interface SampleBody { name: string; description: string; files: WorkflowFile[] }
export interface Rule { id: string; title: string; severity: Severity; category: Category; remediation: string; reference: string; autofix: boolean }
export interface Stats {
  audits: number; pass: number; warn: number; fail: number; critical_findings: number; high_findings: number;
  workflows_scanned: number; avg_score: number | null; avg_score_after_fixes: number | null;
}
export interface AuditResult { id: number | null; name: string; report: Report }
