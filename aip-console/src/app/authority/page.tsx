"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useConsole } from "@/lib/context/ConsoleContext";

export default function AuthorityRoute() {
  const { setActiveTab } = useConsole();
  const router = useRouter();

  useEffect(() => {
    setActiveTab("authority");
    router.replace("/");
  }, [setActiveTab, router]);

  return null;
}
