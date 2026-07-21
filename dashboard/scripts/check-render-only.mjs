// Guard: the dashboard must RENDER pre-computed numbers, never re-DERIVE a defense rate.
// The hazard is computing a rosier rate than the engine measured — i.e. dividing a verdict
// count by `exercised`, or assigning `defense_rate` from arithmetic. Reading `rollups.defense_rate`
// (a property the engine pre-computed) and comparing it (e.g. `=== 1` for a color) is fine, as is
// summing pre-computed per-cell verdict counts for a display badge.
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const roots = ["lib", "components"];
const banned = [
  { re: /\/\s*\w*\.?exercised(_n)?\b/, why: "dividing by exercised to derive a rate" },
  { re: /defense_rate\s*=\s*[^=]/, why: "assigning defense_rate in the UI" },
  { re: /defense_rate\s*[:=]\s*.*[+\-*/]/, why: "computing defense_rate from arithmetic" },
];

let bad = 0;
for (const root of roots) {
  for (const f of readdirSync(root)) {
    if (!/\.tsx?$/.test(f)) continue;
    readFileSync(path.join(root, f), "utf8")
      .split("\n")
      .forEach((line, i) => {
        for (const { re, why } of banned) {
          if (re.test(line)) {
            console.error(`render-only violation ${root}/${f}:${i + 1} (${why}): ${line.trim()}`);
            bad++;
          }
        }
      });
  }
}
if (bad) {
  console.error(`\n${bad} render-only violation(s): the dashboard must not re-derive the defense rate.`);
  process.exit(1);
}
console.log("render-only: clean (dashboard renders the engine's pre-computed numbers only)");
