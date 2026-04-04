/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'sp-bg':      '#0d1117',
        'sp-surface': '#161b22',
        'sp-border':  '#30363d',
        'sp-accent':  '#00ff88',
        'sp-text':    '#e6edf3',
        'sp-muted':   '#8b949e',
        'sev-critical': '#ff4444',
        'sev-high':     '#ff8c00',
        'sev-medium':   '#ffd700',
        'sev-low':      '#00ff88',
        'sev-benign':   '#30363d',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    }
  },
  plugins: [],
}
