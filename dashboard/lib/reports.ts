// Build-time data layer. Reads the committed JSON snapshots + audit JSONL from disk at build
// time (static export). No network, no backend, no secrets. RENDER-ONLY: this module reads and
// formats; it never re-computes a verdict or a rollup (those come straight from the report).

import { promises as fs } from "node:fs";
import path from "node:path";

import type { AuditRecord, RunReport } from "./schema";

const REPORTS_DIR = path.join(process.cwd(), "public", "reports");

export interface IndexEntry {
  run_id: string;
  mode: "gated" | "ungated";
  seed: number;
  generated_at: string;
  git_commit: string;
  report_hash: string;
  defense_rate: number | null;
  exercised: number;
  defended: number;
  na_count: number;
  error_count: number;
  total_attempts: number;
  status: string;
  file: string;
}

export async function readIndex(): Promise<IndexEntry[]> {
  const raw = await fs.readFile(path.join(REPORTS_DIR, "index.json"), "utf8");
  return (JSON.parse(raw).runs ?? []) as IndexEntry[];
}

export async function readRun(file: string): Promise<RunReport> {
  const raw = await fs.readFile(path.join(REPORTS_DIR, file), "utf8");
  return JSON.parse(raw) as RunReport;
}

export async function readAudit(file: string | null): Promise<AuditRecord[]> {
  if (!file) return [];
  const raw = await fs.readFile(path.join(REPORTS_DIR, file), "utf8");
  return raw
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as AuditRecord);
}

export async function loadAll(): Promise<{
  index: IndexEntry[];
  runs: Record<string, RunReport>;
  audits: Record<string, AuditRecord[]>;
}> {
  const index = await readIndex();
  const runs: Record<string, RunReport> = {};
  const audits: Record<string, AuditRecord[]> = {};
  for (const entry of index) {
    const run = await readRun(entry.file);
    runs[entry.mode] = run;
    audits[entry.mode] = await readAudit(run.audit.file);
  }
  return { index, runs, audits };
}
