/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        sentinel: {
          50: "#e6f7ff",
          100: "#b3e6ff",
          200: "#80d4ff",
          300: "#4dc3ff",
          400: "#1ab1ff",
          500: "#0099e6",
          600: "#0077b3",
          700: "#005580",
          800: "#00334d",
          900: "#001a26",
        },
        cyber: {
          bg: "#0a0e17",
          surface: "#111827",
          card: "#1a2332",
          border: "#1e293b",
          muted: "#64748b",
          accent: "#22d3ee",
          green: "#10b981",
          red: "#ef4444",
          amber: "#f59e0b",
          purple: "#a855f7",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
        "slide-in": "slideIn 0.3s ease-out",
      },
      keyframes: {
        glow: {
          "0%": { boxShadow: "0 0 5px rgba(34, 211, 238, 0.2)" },
          "100%": { boxShadow: "0 0 20px rgba(34, 211, 238, 0.4)" },
        },
        slideIn: {
          "0%": { opacity: "0", transform: "translateY(-10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
