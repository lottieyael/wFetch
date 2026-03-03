export const THEMES = {
  midnight: {
    primary: "#00D9FF",
    secondary: "#A78BFA",
    tertiary: "#818CF8",
    background: "linear-gradient(135deg, #000000 0%, #0a0a0f 50%, #050510 100%)",
    textPrimary: "#E0E7FF",
    textSecondary: "rgba(224, 231, 255, 0.5)",
    cardBg: "rgba(255, 255, 255, 0.02)",
    cardBorder: "rgba(167, 139, 250, 0.15)",
    shadowColor: "rgba(0, 0, 0, 0.8)",
    accentShadow: "rgba(0, 217, 255, 0.4)",
    focusRing: "rgba(0, 217, 255, 0.3)",
  },
  system: {
    primary: "#007AFF",
    secondary: "#5E5CE6",
    tertiary: "#AF52DE",
    background: "linear-gradient(135deg, #000000 0%, #1a1a2e 50%, #2b163e 100%)",
    textPrimary: "#ffffff",
    textSecondary: "rgba(255, 255, 255, 0.6)",
    cardBg: "rgba(255, 255, 255, 0.08)",
    cardBorder: "rgba(255, 255, 255, 0.18)",
    shadowColor: "rgba(0, 0, 0, 0.3)",
    accentShadow: "rgba(0, 122, 255, 0.3)",
    focusRing: "rgba(0, 122, 255, 0.2)",
  },
  light: {
    primary: "#2A7A45",
    secondary: "#5CC987",
    tertiary: "#3DD6B0",
    background: "linear-gradient(160deg, #ffffff 0%, #edfaf4 25%, #d0f5e3 55%, #c8f0e8 80%, #e4faf4 100%)",
    textPrimary: "#0c2218",
    textSecondary: "rgba(12, 34, 24, 0.55)",
    cardBg: "rgba(255, 255, 255, 0.55)",
    cardBorder: "rgba(255, 255, 255, 0.88)",
    shadowColor: "rgba(28, 96, 58, 0.18)",
    accentShadow: "rgba(42, 122, 69, 0.4)",
    focusRing: "rgba(42, 122, 69, 0.28)",
  },
  dark: {
    primary: "#FF0000",
    secondary: "#FF5B0F",
    tertiary: "#FCB045",
    background: "linear-gradient(135deg, #1a1a1a 0%, #2d1a1a 50%, #3d2222 100%)",
    textPrimary: "#ffffff",
    textSecondary: "rgba(255, 255, 255, 0.6)",
    cardBg: "rgba(255, 255, 255, 0.06)",
    cardBorder: "rgba(255, 255, 255, 0.12)",
    shadowColor: "rgba(139, 69, 19, 0.25)",
    accentShadow: "rgba(255, 0, 0, 0.3)",
    focusRing: "rgba(255, 0, 0, 0.2)",
  },
  cherry: {
    primary: "#FF1493",
    secondary: "#FF69B4",
    tertiary: "#FFB6C1",
    background: "linear-gradient(135deg, #FFF0F5 0%, #FFE4E1 50%, #FFF5EE 100%)",
    textPrimary: "#2D1B2E",
    textSecondary: "rgba(45, 27, 46, 0.6)",
    cardBg: "rgba(255, 255, 255, 0.9)",
    cardBorder: "rgba(255, 20, 147, 0.15)",
    shadowColor: "rgba(255, 105, 180, 0.2)",
    accentShadow: "rgba(255, 20, 147, 0.3)",
    focusRing: "rgba(255, 20, 147, 0.2)",
  },
};

export function applyTheme(themeName) {
  const selectedTheme = THEMES[themeName] || THEMES.midnight;
  const root = document.documentElement;

  root.style.setProperty("--color-primary", selectedTheme.primary);
  root.style.setProperty("--color-secondary", selectedTheme.secondary);
  root.style.setProperty("--color-tertiary", selectedTheme.tertiary);
  root.style.setProperty("--gradient-background", selectedTheme.background);
  root.style.setProperty("--text-primary", selectedTheme.textPrimary);
  root.style.setProperty("--text-secondary", selectedTheme.textSecondary);
  root.style.setProperty("--card-bg", selectedTheme.cardBg);
  root.style.setProperty("--card-border", selectedTheme.cardBorder);
  root.style.setProperty("--shadow-color", selectedTheme.shadowColor);
  root.style.setProperty("--accent-shadow", selectedTheme.accentShadow);
  root.style.setProperty("--focus-ring", selectedTheme.focusRing);
}
