"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useConsole } from "@/lib/context/ConsoleContext";

export default function TamperRoute() {
  const { setActiveTab } = useConsole();
  const router = useRouter();

  useEffect(() => {
    setActiveTab("tamper");
    router.replace("/");
  }, [setActiveTab, router]);

  return null;
}
