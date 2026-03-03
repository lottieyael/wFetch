import { useEffect, useState } from "react";
import { applyTheme } from "../theme";

export function useThemePreference(effectiveSubscribed) {
  const [saveTheme, setSaveTheme] = useState(
    () => localStorage.getItem("saveTheme") === "true",
  );
  const [theme, setTheme] = useState(() => {
    const shouldSave = localStorage.getItem("saveTheme") === "true";
    return shouldSave ? localStorage.getItem("theme") || "midnight" : "midnight";
  });

  useEffect(() => {
    localStorage.setItem("saveTheme", saveTheme.toString());
  }, [saveTheme]);

  useEffect(() => {
    if (saveTheme) {
      localStorage.setItem("theme", theme);
    } else {
      localStorage.removeItem("theme");
    }
  }, [theme, saveTheme]);

  const FREE_THEMES = ["midnight", "system"];

  useEffect(() => {
    const allowed = effectiveSubscribed || FREE_THEMES.includes(theme);
    applyTheme(allowed ? theme : "midnight");
  }, [theme, effectiveSubscribed]);

  useEffect(() => {
    if (!effectiveSubscribed && !FREE_THEMES.includes(theme)) {
      setTheme("midnight");
    }
  }, [effectiveSubscribed, theme]);
  return { theme, setTheme, saveTheme, setSaveTheme };
}
