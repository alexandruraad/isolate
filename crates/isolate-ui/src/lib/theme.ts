import { useIsolateStore } from "../stores/isolateStore";

export interface ThemeTokens {
  bg: string;
  bgCard: string;
  bgHover: string;
  bgInput: string;
  bgAccentFaint: string;
  border: string;
  borderAccent: string;
  text: string;
  textDim: string;
  textFaint: string;
  accent: string;
  green: string;
  blue: string;
  yellow: string;
  red: string;
  orange: string;
  chartBar: string;
  chartAxis: string;
  tooltipBg: string;
  tooltipBorder: string;
  scanlines: boolean;
}

const CYBER: ThemeTokens = {
  bg:             "#0a0a0a",
  bgCard:         "#0a0f0c",
  bgHover:        "rgba(0,255,159,0.05)",
  bgInput:        "#060d09",
  bgAccentFaint:  "rgba(0,255,159,0.08)",
  border:         "rgba(0,255,159,0.15)",
  borderAccent:   "rgba(0,255,159,0.4)",
  text:           "#c8ffe0",
  textDim:        "#5aff9d",
  textFaint:      "#3c8c63",
  accent:         "#00ff9f",
  green:          "#00ff9f",
  blue:           "#00d4ff",
  yellow:         "#ffe900",
  red:            "#ff3a6e",
  orange:         "#ff8c42",
  chartBar:       "#00ff9f",
  chartAxis:      "#3c8c63",
  tooltipBg:      "#0a0f0c",
  tooltipBorder:  "rgba(0,255,159,0.25)",
  scanlines:      true,
};

const SOC: ThemeTokens = {
  bg:             "#0b0f1a",
  bgCard:         "#101624",
  bgHover:        "rgba(56,189,248,0.05)",
  bgInput:        "#0d1220",
  bgAccentFaint:  "rgba(56,189,248,0.08)",
  border:         "#1a2840",
  borderAccent:   "#253a5c",
  text:           "#e8edf5",
  textDim:        "#8a9bb5",
  textFaint:      "#5a6b82",
  accent:         "#38bdf8",
  green:          "#4ade80",
  blue:           "#38bdf8",
  yellow:         "#f59e0b",
  red:            "#f87171",
  orange:         "#fb923c",
  chartBar:       "#38bdf8",
  chartAxis:      "#5a6b82",
  tooltipBg:      "#101624",
  tooltipBorder:  "#1a2840",
  scanlines:      false,
};

export function useTheme(): ThemeTokens {
  const { theme } = useIsolateStore();
  return theme === "cyber" ? CYBER : SOC;
}
