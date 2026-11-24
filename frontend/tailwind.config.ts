import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./features/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        ashlynx: {
          50: "#f0f9ff",
          100: "#e0f2fe",
          500: "#0284c7",
          700: "#0369a1",
          900: "#0c4a6e"
        },
        severity: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#d97706",
          low: "#2563eb",
          info: "#4b5563"
        }
      }
    }
  },
  plugins: []
};
export default config;
