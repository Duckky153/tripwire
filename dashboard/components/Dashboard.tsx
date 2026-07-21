"use client";

import { useMemo, useState } from "react";

import { ratePct, shortHash, VERDICT_COLOR, VERDICT_LABEL } from "@/lib/format";
import type { IndexEntry } from "@/lib/reports";
import type { AuditRecord, MatrixCell, RunReport, Verdict, VulnClass } from "@/lib/schema";

type Mode = "gated" | "ungated";
type Tab = "matrix" | "trend" | "audit";

interface Props {
  index: IndexEntry[];
  runs: Record<string, RunReport>;
  audits: Record<string, AuditRecord[]>;
}

const VERDICTS: Verdict[] = [
  "blocked", "refused", "pass", "not_applicable", "error", "leaked", "allowed_unsafe",
];

export default function Dashboard({ runs, audits }: Props) {
  const [mode, setMode] = useState<Mode>("gated");
  const [tab, setTab] = useState<Tab>("matrix");
  const [selected, setSelected] = useState<string | null>(null);

  const run = runs[mode];
  const classes = useMemo(() => {
    const m: Record<string, VulnClass> = {};
    run.taxonomy.classes.forEach((c) => (m[c.id] = c));
    return m;
  }, [run]);

  if (!run) return <div className="wrap">No report data committed yet.</div>;
  const r = run.rollups;
  const gated = runs.gated?.rollups;
  const ungated = runs.ungated?.rollups;
  // N/A is counted in CLASSES (each exercised across multiple cases); show classes, not attempts.
  const naClasses = run.matrix.filter((c) => c.cell_verdict === "not_applicable").length;
  const bySurface = r.by_surface;

  return (
    <div className="wrap">
      <header className="masthead">
        <h1>tripwire — vulnerability matrix</h1>
        <p className="thesis">
          A fail-closed action gate measured against a {run.taxonomy.classes.length}-class
          adversarial corpus. No high-stakes action runs without an explicit matching policy
          rule; ambiguity always refuses. Every number below is measured from a committed,
          seed-pinned run — not asserted.
        </p>
      </header>

      <div className="banner">
        <div className="stat">
          <div className="k">Defense rate ({mode})</div>
          <div className={`v ${r.defense_rate === 1 ? "good" : r.defense_rate === 0 ? "bad" : ""}`}>
            {ratePct(r.defense_rate)}
          </div>
          <div className="sub">{r.defended} of {r.exercised} exercised</div>
        </div>
        <div className="stat">
          <div className="k">Unsafe allowed</div>
          <div className={`v ${countCell(run, "allowed_unsafe") ? "bad" : "good"}`}>
            {countAttempts(run, "allowed_unsafe")}
          </div>
          <div className="sub">across {r.exercised} attempts</div>
        </div>
        <div className="stat">
          <div className="k">Leaked</div>
          <div className={`v ${countAttempts(run, "leaked") ? "bad" : "good"}`}>
            {countAttempts(run, "leaked")}
          </div>
          <div className="sub">output-guard misses</div>
        </div>
        <div className="stat">
          <div className="k">Not applicable</div>
          <div className="v">{naClasses}</div>
          <div className="sub">classes · model-behavior / infra</div>
        </div>
        <div className="stat">
          <div className="k">Audit chain</div>
          <div className={`v ${run.audit.chain_verified ? "good" : ""}`}>
            {run.audit.chain_verified === null ? "—" : run.audit.chain_verified ? "verified" : "BROKEN"}
          </div>
          <div className="sub">{run.audit.record_count} records</div>
        </div>
      </div>

      {gated && ungated && (
        <p className="thesis" style={{ marginTop: -6 }}>
          Delta vs. the undefended baseline: <strong className="good">{ratePct(gated.defense_rate)}</strong>{" "}
          gated vs. <strong className="bad">{ratePct(ungated.defense_rate)}</strong> ungated
          (n={gated.exercised}). The baseline proves the attacks are real; the gate is what stops them.
        </p>
      )}

      {bySurface && (
        <p className="thesis" style={{ marginTop: -2 }}>
          Two defense surfaces, reported separately — never conflated into one score:{" "}
          <strong>action authorization {bySurface.action.defended}/{bySurface.action.exercised}</strong>{" "}
          (the by-construction guarantee — no high-stakes action without an explicit matching rule,
          property-tested, every decision in the tamper-evident audit log) ·{" "}
          <strong>output disclosure {bySurface.output.defended}/{bySurface.output.exercised}</strong>{" "}
          (detection-based defense-in-depth — a shape filter is best-effort and bypassable by
          obfuscation; the guarantee deliberately lives at the action layer, where it can be proven).
        </p>
      )}

      <div className="tabs">
        <button className={`tab ${tab === "matrix" ? "active" : ""}`} onClick={() => setTab("matrix")}>Matrix</button>
        <button className={`tab ${tab === "trend" ? "active" : ""}`} onClick={() => setTab("trend")}>Trend</button>
        <button className={`tab ${tab === "audit" ? "active" : ""}`} onClick={() => setTab("audit")}>Audit trail</button>
        <span style={{ flex: 1 }} />
        <div className="toggle">
          <button className={mode === "gated" ? "on" : ""} onClick={() => setMode("gated")}>Gated</button>
          <button className={mode === "ungated" ? "on" : ""} onClick={() => setMode("ungated")}>Ungated baseline</button>
        </div>
      </div>

      {tab === "matrix" && (
        <>
          <Legend />
          <div className="matrix">
            {run.matrix.map((cell) => (
              <CellCard
                key={cell.class_id}
                cell={cell}
                cls={classes[cell.class_id]}
                onClick={() => setSelected(cell.class_id)}
              />
            ))}
          </div>
        </>
      )}

      {tab === "trend" && <Trend runs={runs} />}
      {tab === "audit" && <Audit records={audits[mode] ?? []} mode={mode} />}

      {selected && classes[selected] && (
        <Drawer
          cls={classes[selected]}
          cell={run.matrix.find((m) => m.class_id === selected)!}
          audit={audits[mode] ?? []}
          onClose={() => setSelected(null)}
        />
      )}

      <div className="honest">
        <strong>Honesty.</strong> 100% gated defense is the expected correct behavior of a
        deny-by-default gate against attacks that all violate the reference policy — not a
        surprising score. The value is the by-construction guarantee (property-tested) plus the
        tamper-evident audit trail. A permissive custom policy can still authorize a harmful
        action. The {naClasses} N/A classes are model-behavior / infra classes a deterministic
        action-gate mock cannot honestly exercise; they are greyed and excluded from every
        denominator. Run <code>{run.provenance.reproducible_cmd}</code> · seed{" "}
        {run.provenance.seed} · commit <code>{shortHash(run.provenance.git_commit)}</code> ·
        report <code>{shortHash(run.report_hash)}</code> · redaction scan{" "}
        {run.redaction_attestation.independent_scan ? "clean" : "—"} ({run.redaction_attestation.scanner}).
      </div>
    </div>
  );
}

function countAttempts(run: RunReport, v: Verdict): number {
  return run.matrix.reduce((n, c) => n + (c.verdicts[v] ?? 0), 0);
}
function countCell(run: RunReport, v: Verdict): number {
  return run.matrix.filter((c) => c.cell_verdict === v).length;
}

function Legend() {
  return (
    <div className="legend">
      {VERDICTS.map((v) => (
        <span key={v} style={{ ["--c" as string]: VERDICT_COLOR[v] }}>
          <i style={{ background: VERDICT_COLOR[v], display: "inline-block", width: 10, height: 10, borderRadius: 3, marginRight: 5 }} />
          {VERDICT_LABEL[v]}
        </span>
      ))}
    </div>
  );
}

function CellCard({ cell, cls, onClick }: { cell: MatrixCell; cls?: VulnClass; onClick: () => void }) {
  const color = VERDICT_COLOR[cell.cell_verdict];
  const denom = cell.exercised_n;
  const defended = (cell.verdicts.blocked ?? 0) + (cell.verdicts.refused ?? 0) + (cell.verdicts.pass ?? 0);
  return (
    <div className="cell" onClick={onClick}>
      <div className="bar" style={{ background: color }} />
      <div className="cid mono">{cell.class_id}</div>
      <div className="cname">{cls?.name ?? cell.class_id}</div>
      <span className="pill" style={{ background: color }}>{VERDICT_LABEL[cell.cell_verdict]}</span>
      <div className="den">
        {denom > 0 ? `defended ${defended}/${denom}` : "not exercised (N/A)"}
      </div>
    </div>
  );
}

function Trend({ runs }: { runs: Record<string, RunReport> }) {
  // Honest trend with only the committed baseline runs: discrete points, no smoothing, no CI
  // (Wilson band only at n>=30 runs). One gated + one ungated point per the committed snapshots.
  return (
    <div className="section">
      <h2>Trend</h2>
      <p className="note">
        Baseline building (1/5 runs). Points are plotted discretely — no moving average, no
        trendline, no confidence band — until at least 5 dated runs exist. Each point is the
        defense rate of one committed snapshot, shown with its exercised denominator and the
        N/A classes it excludes — the rate is never presented without that coverage context.
      </p>
      <div className="dots">
        {Object.values(runs).map((rr) => (
          <div className="dot" key={rr.provenance.mode} style={{ minWidth: 96 }}>
            <div
              className="d"
              style={{
                background:
                  rr.rollups.defense_rate === 1 ? "#36c6a0"
                  : rr.rollups.defense_rate === 0 ? "#c0392b" : "#b78a17",
                marginBottom: `${(rr.rollups.defense_rate ?? 0) * 36}px`,
              }}
            />
            {rr.provenance.mode}
            <span className="mono">{ratePct(rr.rollups.defense_rate)}</span>
            <span className="mono" style={{ fontSize: 10 }}>
              n={rr.rollups.exercised} · N/A {rr.matrix.filter((c) => c.cell_verdict === "not_applicable").length}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Audit({ records, mode }: { records: AuditRecord[]; mode: Mode }) {
  if (mode === "ungated") {
    return (
      <div className="section">
        <h2>Audit trail</h2>
        <p className="note">The ungated baseline runs no gate, so it produces no audit records — that is the point.</p>
      </div>
    );
  }
  return (
    <div className="section">
      <h2>Audit trail ({records.length} hash-chained records)</h2>
      <p className="note">
        Every gate decision, tamper-evident via a SHA-256 hash chain. Args and world-facts are
        masked at write time (deny-by-default redaction); only structural fields appear in clear.
      </p>
      <table>
        <thead>
          <tr><th>tool</th><th>verdict</th><th>reason</th><th>rule</th><th>escalate</th><th>record_hash</th></tr>
        </thead>
        <tbody>
          {records.slice(0, 120).map((rec, i) => (
            <tr key={i}>
              <td className="mono">{rec.tool}</td>
              <td><span className="chip" style={{ background: chipFor(rec.final_verdict) }}>{rec.final_verdict}</span></td>
              <td className="mono">{rec.reason_code}</td>
              <td className="mono">{rec.matched_rule_id ?? "—"}</td>
              <td>{rec.escalate ? "yes" : "—"}</td>
              <td className="mono">{shortHash(String(rec.record_hash))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function chipFor(v: string): string {
  if (v === "allow") return "#7d1a13";
  if (v === "escalate") return "#b78a17";
  return "#2f9e6f";
}

function Drawer({
  cls, cell, audit, onClose,
}: { cls: VulnClass; cell: MatrixCell; audit: AuditRecord[]; onClose: () => void }) {
  const refs = cell.attempts
    .filter((a) => a.audit_ref)
    .flatMap((a) => audit.slice(a.audit_ref![0], a.audit_ref![1]));
  return (
    <div className="drawer">
      <button className="close" onClick={onClose}>×</button>
      <div className="cid mono">{cls.id} · {cls.category} · {cls.severity}</div>
      <h3>{cls.name}</h3>
      <div className="kv"><div className="k">Description</div><div className="v">{cls.description}</div></div>
      <div className="kv"><div className="k">Example attack</div><div className="v mono" style={{ fontSize: 12 }}>{cls.example_attack}</div></div>
      <div className="kv"><div className="k">Expected fail-closed behavior</div><div className="v">{cls.expected_fail_closed_behavior}</div></div>
      <div className="kv"><div className="k">Detection signal</div><div className="v">{cls.detection_signal}</div></div>
      <div className="kv">
        <div className="k">Crosswalk</div>
        <div className="v">{cls.crosswalk.length ? cls.crosswalk.map((c) => <span className="tag" key={c}>{c}</span>) : <em>none — content/brand-safety class</em>}</div>
      </div>
      <div className="kv">
        <div className="k">Attempts ({cell.cell_verdict})</div>
        <div className="v">
          <table>
            <thead><tr><th>case</th><th>origin</th><th>verdict</th></tr></thead>
            <tbody>
              {cell.attempts.map((a) => (
                <tr key={a.attempt_id}>
                  <td className="mono">{a.attempt_id}</td>
                  <td>{a.origin}</td>
                  <td><span className="chip" style={{ background: VERDICT_COLOR[a.verdict as Verdict] ?? "#3a4150" }}>{a.verdict}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {refs.length > 0 && (
        <div className="kv">
          <div className="k">Gate decisions for this class</div>
          <div className="v">
            <table>
              <thead><tr><th>tool</th><th>verdict</th><th>reason</th></tr></thead>
              <tbody>
                {refs.slice(0, 12).map((rec, i) => (
                  <tr key={i}>
                    <td className="mono">{rec.tool}</td>
                    <td><span className="chip" style={{ background: chipFor(rec.final_verdict) }}>{rec.final_verdict}</span></td>
                    <td className="mono">{rec.reason_code}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
