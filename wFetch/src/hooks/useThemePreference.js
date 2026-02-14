import { useEffect, useState } from "react";
import { applyTheme } from "../theme";

export function useThemePreference(effectiveSubscribed) {
  const [saveTheme, setSaveTheme] = useState(
    () => localStorage.getItem("saveTheme") === "true",
  );

  const [theme, setTheme] = useState(() => {
    const shouldSave = localStorage.getItem("saveTheme") === "true";
    return shouldSave ? localStorage.getItem("theme") || "system" : "system";
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

  useEffect(() => {
    applyTheme(effectiveSubscribed ? theme : "system");
  }, [theme, effectiveSubscribed]);

  useEffect(() => {
    if (!effectiveSubscribed && theme !== "system") {
      setTheme("system");
    }
  }, [effectiveSubscribed, theme]);

  return { theme, setTheme, saveTheme, setSaveTheme };
}
