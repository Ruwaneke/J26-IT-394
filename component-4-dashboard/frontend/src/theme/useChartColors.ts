import { useEffect, useState } from "react";

// Chart colours come from VS Code theme variables (with browser fallbacks in
// styles.css). SVG attributes need concrete colours, so we resolve the CSS
// custom properties and re-read them when VS Code switches theme (it changes
// the body class and the inline style variables).
const TOKENS = {
  blue: "--c-blue",
  orange: "--c-orange",
  green: "--c-green",
  red: "--c-red",
  purple: "--c-purple",
  yellow: "--c-yellow",
  fg: "--c-fg",
  muted: "--c-muted",
  grid: "--c-grid",
  bg: "--c-bg",
} as const;

export type ChartColors = Record<keyof typeof TOKENS, string>;

function read(): ChartColors {
  const style = getComputedStyle(document.documentElement);
  const out = {} as ChartColors;
  for (const [key, prop] of Object.entries(TOKENS)) {
    out[key as keyof ChartColors] = style.getPropertyValue(prop).trim() || "#888888";
  }
  return out;
}

export function useChartColors(): ChartColors {
  const [colors, setColors] = useState<ChartColors>(read);
  useEffect(() => {
    const update = () => setColors(read());
    const observer = new MutationObserver(update);
    observer.observe(document.body, { attributes: true, attributeFilter: ["class", "style"] });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style"] });
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", update);
    return () => {
      observer.disconnect();
      media.removeEventListener("change", update);
    };
  }, []);
  return colors;
}
