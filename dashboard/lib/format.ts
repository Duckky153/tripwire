// Pure presentation helpers — formatting only, never aggregation. Every number shown comes
// straight from the report's pre-computed rollups/cells; nothing here sums verdicts.

import type { Verdict } from "./schema";

export const VERDICT_COLOR: Record<Verdict, string> = {
  pass: "#1f8a4c",
  refused: "#2f9e6f",
  blocked: "#2f9e6f",
  error: "#b78a17",
  leaked: "#c0392b",
  allowed_unsafe: "#7d1a13",
  not_applicable: "#3a4150",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  pass: "Pass",
  refused: "Refused",
  blocked: "Blocked",
  error: "Error",
  leaked: "Leaked",
  allowed_unsafe: "Allowed-unsafe",
  not_applicable: "N/A",
};

export function ratePct(rate: number | null): string {
  return rate === null ? "—" : `${(rate * 100).toFixed(1)}%`;
}

export function shortHash(h: string): string {
  return h ? `${h.slice(0, 12)}…` : "—";
}
