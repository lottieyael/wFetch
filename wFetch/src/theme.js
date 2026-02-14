export const THEMES = {
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
    primary: "#2D7A4A",
    secondary: "#74D19A",
    tertiary: "#54E9C9",
    background: "linear-gradient(135deg, #F5F5F5 0%, #E8F5E9 50%, #E0F2F1 100%)",
    textPrimary: "#1a1a1a",
    textSecondary: "rgba(26, 26, 26, 0.6)",
    cardBg: "rgba(255, 255, 255, 0.85)",
    cardBorder: "rgba(26, 26, 26, 0.08)",
    shadowColor: "rgba(45, 122, 74, 0.15)",
    accentShadow: "rgba(45, 122, 74, 0.3)",
    focusRing: "rgba(45, 122, 74, 0.2)",
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
};

export function applyTheme(themeName) {
  const selectedTheme = THEMES[themeName] || THEMES.system;
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
