import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./features/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        canvas: "var(--canvas)",
        surface: {
          DEFAULT: "var(--surface)",
          subtle: "var(--surface-subtle)",
          elevated: "var(--surface-elevated)",
        },
        ink: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        swiss: {
          border: "var(--border-swiss)",
          "border-subtle": "var(--border-subtle)",
          "border-strong": "var(--border-strong)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          hover: "var(--accent-hover)",
          subtle: "var(--accent-subtle)",
        },
        severity: {
          critical: "#C62828",
          high: "#E53935",
          medium: "#D97706",
          low: "#2563EB",
          info: "#64748B",
          success: "#15803D",
          active: "#2563EB",
          disabled: "#A3A3A3",
        }
      },
      fontFamily: {
        display: ["var(--font-space-grotesk)", "Space Grotesk", "Helvetica Neue", "Arial", "sans-serif"],
        sans: ["var(--font-plus-jakarta)", "Plus Jakarta Sans", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono: ["var(--font-ibm-plex-mono)", "IBM Plex Mono", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      borderRadius: {
        none: "0px",
        xs: "1px",
        sm: "2px",
        DEFAULT: "2px",
        md: "3px",
      },
      boxShadow: {
        "swiss-sm": "0 1px 2px 0 rgba(0, 0, 0, 0.05)",
        "swiss-md": "0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -1px rgba(0, 0, 0, 0.04)",
        "swiss-focus": "0 0 0 2px var(--canvas), 0 0 0 4px var(--accent)",
      }
    }
  },
  plugins: []
};

export default config;
