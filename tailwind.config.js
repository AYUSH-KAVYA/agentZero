/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
        cyber: {
          dark: '#080d1a',
          darker: '#040711',
          card: '#0e1726',
          border: '#1e293b',
          accent: '#38bdf8',
          accentBlue: '#2563eb',
          warning: '#f59e0b',
          danger: '#ef4444',
          info: '#38bdf8',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'skeuo': '0 12px 30px -6px rgba(0, 0, 0, 0.5), inset 0 1px 1px 0 rgba(255, 255, 255, 0.12)',
        'skeuo-btn': '0 4px 14px rgba(14, 165, 233, 0.35), inset 0 1px 1px 0 rgba(255, 255, 255, 0.4)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.4)',
      },
    },
  },
  plugins: [],
};
