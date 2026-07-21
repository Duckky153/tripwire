import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "tripwire — vulnerability matrix",
  description:
    "Fail-closed action gate + adversarial red-team harness for tool-using agents. Real measured numbers, honest denominators.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
