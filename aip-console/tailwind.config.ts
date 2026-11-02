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
        corporate: {
          primary: "#1A2B3C", // Deep slate (primary)
          secondary: "#0B1F2E", // Navy (secondary)
          accent: "#2E7D32", // Refined emerald
          steel: "#607D8B", // Steel gray
          info: "#3F6E9A", // Muted blue (informational)
          warning: "#B7791F", // Ochre (warning)
          danger: "#C62828", // Brick red (failure / tamper)
          // Lighter tints for text on dark surfaces (>= 4.5:1 on #0E131F)
          "accent-light": "#4CAF50",
          "steel-light": "#90A4AE",
          "info-light": "#64B5F6",
          "warning-light": "#F6AD55",
          "danger-light": "#EF5350",
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
        destructive: {
          DEFAULT: "#C62828",
          foreground: "#F8FAFC",
        },
        success: {
          DEFAULT: "#2E7D32",
          foreground: "#F8FAFC",
        },
        warning: {
          DEFAULT: "#B7791F",
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
        "steel-glow": "0 0 12px -2px rgba(96, 125, 139, 0.40)",
        "accent-glow": "0 0 12px -2px rgba(46, 125, 50, 0.40)",
        "danger-glow": "0 0 12px -2px rgba(198, 40, 40, 0.40)",
        card: "0 4px 20px -2px rgba(0, 0, 0, 0.55), 0 0 0 1px rgba(34, 47, 70, 0.8)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
