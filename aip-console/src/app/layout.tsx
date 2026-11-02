import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { AppProviders } from "@/components/providers/AppProviders";
import ConsoleHeader from "@/components/brand/ConsoleHeader";

export const metadata: Metadata = {
  title: "SYNTRIASS | AIP Enterprise Accountability Console",
  description:
    "Verify AIP EvidencePackets, inspect delegation chains, and review authority scopes for AI agents. Verification runs locally in WebAssembly.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen bg-obsidian-950 text-foreground antialiased selection:bg-corporate-steel/25 selection:text-corporate-steel-light">
        <AppProviders>
          <div className="relative flex min-h-screen flex-col">
            <ConsoleHeader />
            <main className="flex-1 flex flex-col w-full max-w-[1720px] mx-auto p-4 sm:p-6 lg:p-8">
              {children}
            </main>
            <footer className="border-t border-obsidian-800 bg-obsidian-950 py-4 px-6 text-xs text-slate-500">
              <div className="max-w-[1720px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
                <span>SYNTRIASS Accountability Console • AIP-1 wire format</span>
                <span className="text-corporate-steel-light/70">
                  WebAssembly Verification Engine (aip-wasm)
                </span>
                <nav aria-label="Legal" className="flex items-center gap-4 text-xs">
                  <Link href="/privacy" className="text-slate-500 hover:text-slate-300 transition-colors">
                    Privacy
                  </Link>
                  <Link href="/terms" className="text-slate-500 hover:text-slate-300 transition-colors">
                    Terms
                  </Link>
                </nav>
              </div>
            </footer>
          </div>
        </AppProviders>
      </body>
    </html>
  );
}
