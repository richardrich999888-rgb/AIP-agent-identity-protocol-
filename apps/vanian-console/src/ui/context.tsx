"use client";
import { createContext, useContext } from "react";
import type { Mode, Role, Bundle, Entry, PageDef } from "../types";
export interface Desk {
  page: PageDef;
  selectedRowId?: string;
  mode: Mode;
  role: Role;
  params: URLSearchParams;
  data?: Bundle;
  go: (href: string) => void;
  set: (changes: Record<string, string | null>) => void;
  open: (row: Entry, slug?: string) => void;
  toast: (message: string) => void;
  refresh: () => void;
  modal: (s: string) => void;
  changeMode: (mode: Mode) => void;
  changeRole: (role: Role) => Promise<void>;
  command: boolean;
  toggleCommand: () => void;
}
export const Context = createContext<Desk | null>(null);
export const useDesk = () => useContext(Context)!;
export async function request<T = any>(
  api: string,
  mode: Mode,
  params: URLSearchParams,
  body?: unknown,
): Promise<T> {
  const qs = new URLSearchParams(params);
  qs.set("mode", mode);
  const res = await fetch("/api/" + api + "?" + qs.toString(), {
    credentials: "same-origin",
    cache: "no-store",
    ...(body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
  });
  const data = (await res.json().catch(() => ({}))) as T & {
    error?: { message?: string; code?: string };
  };
  if (!res.ok)
    throw Object.assign(
      new Error(
        data.error?.message || "The workspace could not complete this request.",
      ),
      { code: data.error?.code || "REQUEST_FAILED", status: res.status },
    );
  return data;
}
