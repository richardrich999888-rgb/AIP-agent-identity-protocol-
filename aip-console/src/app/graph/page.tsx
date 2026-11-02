"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useConsole } from "@/lib/context/ConsoleContext";

export default function GraphRoute() {
  const { setActiveTab } = useConsole();
  const router = useRouter();

  useEffect(() => {
    setActiveTab("graph");
    router.replace("/");
  }, [setActiveTab, router]);

  return null;
}
