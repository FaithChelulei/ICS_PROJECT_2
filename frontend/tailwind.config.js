/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      // Warm, friendly palette (cream + deep teal + coral), matching the
      // reference design Faith asked for -- replaces the earlier cool
      // blue/slate theme everywhere these tokens are used, without
      // touching component structure or page logic.
      colors: {
        ink: '#211C16',
        cream: {
          DEFAULT: '#FBF6ED',
          100: '#F6EFE2',
          200: '#EFE4D0',
        },
        // Deep teal -- primary buttons, links, active nav, focus rings.
        brand: {
          50: '#EBF4F0',
          100: '#D3E7DD',
          200: '#A9D0BC',
          300: '#7EB89B',
          400: '#53A079',
          500: '#2F8763',
          600: '#1F6D52',
          700: '#155242',
        },
        // Warm coral -- secondary accent used sparingly (CTA banners,
        // highlight badges, the odd stat).
        coral: {
          50: '#FDEEE6',
          100: '#FBDBC9',
          400: '#F0A27B',
          500: '#E8835A',
          600: '#D96A3E',
        },
        peach: '#F8E9D6',
        mint: '#DCEEE1',
        sky: '#E1EBF2',
        // Dark section/sidebar background (Security Auditor portal, the
        // login hero panel).
        navy: {
          900: '#17212A',
          800: '#1F2B35',
          700: '#2A3742',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        // Rounded, friendly display face for big headlines -- body copy
        // stays on Inter for readability.
        display: ['Quicksand', 'Inter', 'ui-sans-serif', 'sans-serif'],
        mono: ['DM Mono', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px 0 rgba(33, 28, 22, 0.05), 0 4px 14px 0 rgba(33, 28, 22, 0.06)',
      },
      borderRadius: {
        xl: '1rem',
        '2xl': '1.5rem',
      },
    },
  },
  plugins: [],
};
