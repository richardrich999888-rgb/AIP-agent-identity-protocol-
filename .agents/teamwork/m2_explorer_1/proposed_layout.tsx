import type { Metadata } from "next";
import "./globals.css";
import { ConsoleProvider } from "@/lib/context/ConsoleContext";
import ConsoleHeader from "@/components/navigation/ConsoleHeader";

export const metadata: Metadata = {
  title: "SYNTRIASS | AIP Enterprise Accountability Console",
  description:
    "High-assurance cryptographic verification and interactive accountability infrastructure for autonomous AI agents.",
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
      <body className="min-h-screen bg-obsidian-950 text-foreground antialiased selection:bg-cyber-cyan/30 selection:text-cyber-cyan">
        <ConsoleProvider>
          <div className="relative flex min-h-screen flex-col">
            <ConsoleHeader />
            <main className="flex-1 flex flex-col w-full max-w-[1720px] mx-auto p-4 sm:p-6 lg:p-8">
              {children}
            </main>
            <footer className="border-t border-obsidian-800 bg-obsidian-950 py-4 px-6 text-center text-xs text-slate-500 font-mono">
              <div className="max-w-[1720px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
                <span>
                  SYNTRIASS Enterprise Accountability Infrastructure • AIP-1 Wire Standard
                </span>
                <span className="text-cyber-cyan/80">
                  Zero-JS WebAssembly Verification Engine
                </span>
              </div>
            </footer>
          </div>
        </ConsoleProvider>
      </body>
    </html>
  );
}
