import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export interface LegalSection {
  heading: string;
  body: string;
}

interface LegalPageProps {
  title: string;
  updated: string;
  sections: LegalSection[];
}

export function LegalPage({ title, updated, sections }: LegalPageProps) {
  return (
    <article className="max-w-3xl w-full mx-auto py-6 space-y-8">
      <Link
        href="/"
        className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-slate-100 transition-colors"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        Back to console
      </Link>

      <header className="space-y-1 border-b border-obsidian-700 pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
        <p className="text-xs font-mono text-slate-500">Last updated: {updated}</p>
        <p className="text-xs text-corporate-warning-light">
          Placeholder text. Replace with reviewed legal copy before production use.
        </p>
      </header>

      {sections.map((s) => (
        <section key={s.heading} className="space-y-2">
          <h2 className="text-base font-semibold text-slate-200">{s.heading}</h2>
          <p className="text-sm leading-relaxed text-slate-400">{s.body}</p>
        </section>
      ))}
    </article>
  );
}
