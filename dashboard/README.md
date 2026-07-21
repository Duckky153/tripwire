# tripwire dashboard

A **fully static** Next.js export (`output: "export"`) — no backend, no server functions, no
secrets. It reads the committed JSON snapshots in `public/reports/` at **build time** and renders
the vulnerability matrix, the gated/ungated delta, per-class drilldowns, the audit trail, and the
trend. All numbers come straight from the engine's pre-computed `rollups`/`verdicts`; the
dashboard never re-aggregates (enforced by `scripts/check-render-only.mjs`).

Because it is a static export, the server-side Next.js CVE class does not apply to the deployed
site; the dependency is still pinned to a patched release.

## Develop

```bash
cd dashboard
npm install
npm run build              # -> out/  (static HTML/JS)
npm run check:render-only  # guard: no verdict re-aggregation in the UI
npx serve out              # preview locally
```

## Deploy (one command — you run it; the build needs no secrets)

**Vercel** (recommended):

```bash
cd dashboard && npx vercel deploy --prod
```

**GitHub Pages** (zero extra accounts — set the repo subpath):

```bash
cd dashboard && BASE_PATH=/<repo-name> npm run build   # then publish out/ to gh-pages
```

## Refreshing the data

```bash
# from the repo root — regenerates dashboard/public/reports/*
tripwire run --suite default --seed 42 --mode both
```
