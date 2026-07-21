// TypeScript types mirroring schema/run-report-v1.json. The dashboard RENDERS these numbers;
// it never re-aggregates them (the Python engine is the single source of truth for rollups).

export type Verdict =
  | "pass"
  | "refused"
  | "blocked"
  | "error"
  | "leaked"
  | "allowed_unsafe"
  | "not_applicable";

export interface VulnClass {
  id: string;
  name: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  applicability: string;
  crosswalk: string[];
  description: string;
  example_attack: string;
  expected_fail_closed_behavior: string;
  detection_signal: string;
}

export interface Attempt {
  attempt_id: string;
  origin: "hand-written" | "templated";
  mode: "gated" | "ungated";
  verdict: string;
  audit_ref: [number, number] | null;
}

export type Surface = "action" | "output" | "na";

export interface MatrixCell {
  class_id: string;
  surface: Surface;
  verdicts: Record<string, number>;
  cell_verdict: Verdict;
  exercised_n: number;
  attempts: Attempt[];
}

export interface SurfaceTally {
  defended: number;
  exercised: number;
}

export interface Rollups {
  defended: number;
  exercised: number;
  defense_rate: number | null;
  na_count: number;
  error_count: number;
  by_severity: Record<string, SurfaceTally>;
  // Two defense surfaces, never conflated: action = the by-construction gate guarantee;
  // output = detection-based defense-in-depth.
  by_surface: { action: SurfaceTally; output: SurfaceTally };
}

export interface RunReport {
  schema_version: "run-report-v1";
  run_id: string;
  report_hash: string;
  provenance: {
    git_commit: string;
    seed: number;
    reproducible_cmd: string;
    engine_version: string;
    mode: "gated" | "ungated";
    generated_at: string;
  };
  taxonomy: { catalog_hash: string; classes: VulnClass[] };
  matrix: MatrixCell[];
  rollups: Rollups;
  redaction_attestation: { independent_scan: boolean; scanner: string };
  audit: { chain_verified: boolean | null; record_count: number; file: string | null };
  status: "complete" | "partial";
}

export interface AuditRecord {
  ts: string;
  trace_id: string;
  tool: string;
  principal_role: string;
  verdict: string;
  vote: string;
  final_verdict: string;
  reason_code: string;
  matched_rule_id: string | null;
  escalate: boolean;
  constraints_evaluated: [string, boolean][];
  prev_hash: string;
  record_hash: string;
  [k: string]: unknown;
}
