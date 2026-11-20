import Console from "../../src/ui/Console";
import { bySlug } from "../../src/navigation";
import { notFound } from "next/navigation";
export default async function Page({
  params,
}: {
  params: Promise<{ view: string[] }>;
}) {
  const { view } = await params;
  if (view.length !== 1 || !bySlug[view[0]]) notFound();
  return <Console initial={view[0]} />;
}
