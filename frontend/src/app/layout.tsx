import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PenTest Agent — Agentic Vulnerability Assessment",
  description: "AI-powered penetration testing that crawls, scans, and autonomously attempts to reproduce every vulnerability with a full PoC report.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
