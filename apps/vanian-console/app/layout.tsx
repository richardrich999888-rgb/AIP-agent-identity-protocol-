import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "VANIAN · AI Security Control Plane",
  description:
    "AI security, execution accountability and independent evidence.",
  icons: { icon: "/brand/icon.png" },
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
