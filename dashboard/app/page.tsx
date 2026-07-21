import Dashboard from "@/components/Dashboard";
import { loadAll } from "@/lib/reports";

// Server component: reads the committed snapshots at BUILD time and hands them to the
// client dashboard. No data is fetched at runtime — this is a fully static export.
export default async function Page() {
  const { index, runs, audits } = await loadAll();
  return <Dashboard index={index} runs={runs} audits={audits} />;
}
