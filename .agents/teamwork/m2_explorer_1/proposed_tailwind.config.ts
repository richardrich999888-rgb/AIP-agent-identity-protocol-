import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: "#080B11", // Deepest background void
          900: "#0E131F", // Surface 1: Cards, Panels
          850: "#121929", // Surface 1.5: Hover states, panel headers
          800: "#161F33", // Surface 2: Elevated surfaces, tables, inputs
          700: "#222F46", // Structural border hairline
          600: "#334155", // Subdued borders
        },
        cyber: {
          cyan: "#00E5FF",      // Electric cyan primary brand accent
          green: "#00E676",     // Level 3 Counterparty Signed / Verified green
          amber: "#FFB300",     // Level 1 Agent Signed / Warning amber
          red: "#FF1744",       // Tamper alert / Failure red
          indigo: "#6366F1",    // Cryptographic signature indigo
          blue: "#3B82F6",      // Secondary gradient blue
          slate: "#64748B",     // Level 0 Unverified slate
        },
        background: "#080B11",
        surface: "#0E131F",
        "surface-elevated": "#161F33",
        border: "#222F46",
        foreground: "#F8FAFC",
        muted: {
          DEFAULT: "#161F33",
          foreground: "#94A3B8",
        },
        primary: {
          DEFAULT: "#00E5FF",
          foreground: "#080B11",
        },
        secondary: {
          DEFAULT: "#6366F1",
          foreground: "#F8FAFC",
        },
        accent: {
          DEFAULT: "#00E5FF",
          foreground: "#080B11",
        },
        destructive: {
          DEFAULT: "#FF1744",
          foreground: "#F8FAFC",
        },
        success: {
          DEFAULT: "#00E676",
          foreground: "#080B11",
        },
        warning: {
          DEFAULT: "#FFB300",
          foreground: "#080B11",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      boxShadow: {
        "cyan-glow": "0 0 20px -3px rgba(0, 229, 255, 0.35)",
        "green-glow": "0 0 20px -3px rgba(0, 230, 118, 0.35)",
        "amber-glow": "0 0 20px -3px rgba(255, 179, 0, 0.35)",
        "red-glow": "0 0 20px -3px rgba(255, 23, 68, 0.35)",
        "card-cyber": "0 4px 20px -2px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(34, 47, 70, 0.8)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
