/** @type {import('tailwindcss').Config} */

// Paleta de marca CyberDefense AI, tomada de los SVG oficiales del logo
// (frontend/src/assets/cyberdefense_logo*.svg):
//   cian  #67e8f9 · sky #38bdf8 · azul #2563eb
//   azul marino profundo #0a1222 / #16294a · texto #e6edf6 · gris azulado #9fb0c8
//
// "gray" sustituye a la escala neutra de Tailwind por una azul marino: en modo
// oscuro los fondos y paneles quedan dentro de la familia del escudo, y en modo
// claro el remapeo de index.css devuelve una escala clara equivalente.
const brand = {
  gray: {
    50: '#f7faff',
    100: '#e9f1fb',
    200: '#d5e2f2',
    300: '#bacbe3',
    400: '#9fb0c8',
    500: '#7b8da7',
    600: '#5d6f8b',
    700: '#3f5070',
    800: '#1b2740',
    900: '#0e1829',
    950: '#070d1a',
  },
  // "blue" pasa a ser la rampa cian->azul de la marca (sky-300 a blue-700).
  blue: {
    50: '#eff9ff',
    100: '#dff2fe',
    200: '#bae6fd',
    300: '#7dd3fc',
    400: '#38bdf8',
    500: '#0ea5e9',
    600: '#2563eb',
    700: '#1d4ed8',
    800: '#1e40af',
    900: '#1e3a8a',
    950: '#172554',
  },
};

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: brand,
    },
  },
  plugins: [],
};
