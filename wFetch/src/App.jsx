import { useEffect, useState } from "react";
import "./App.css";
import { useEntitlements } from "./hooks/useEntitlements";
import { useMonitorSettings } from "./hooks/useMonitorSettings";
import { useSystemInfo } from "./hooks/useSystemInfo";
import { useThemePreference } from "./hooks/useThemePreference";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

function App() {
  const [currentPage, setCurrentPage] = useState("overview");
  const [language, setLanguage] = useState(() => localStorage.getItem("language") || "en");
  const [isExiting, setIsExiting] = useState(false);

  const { bits, waiting, mood } = useSystemInfo();
  const {
    checkoutUrl,
    devUnlockAllowed,
    isDevBuild,
    entitlements,
    setEntitlements,
    entitlementsLoading,
    isSubscribed,
    devUnlocked,
    setDevUnlocked,
    effectiveSubscribed,
  } = useEntitlements();

  const { theme, setTheme, saveTheme, setSaveTheme } = useThemePreference(effectiveSubscribed);

  const {
    monitorEnabled,
    setMonitorEnabled,
    monitorSensitivity,
    setMonitorSensitivity,
    incidents,
    samples,
    deleteIncident,
    clearIncidents,
  } = useMonitorSettings();

  useEffect(() => {
    localStorage.setItem("language", language);
  }, [language]);

  const navigateTo = (page) => {
    setIsExiting(true);
    setTimeout(() => {
      setCurrentPage(page);
      setIsExiting(false);
    }, 300);
  };

  if (waiting) {
    return (
      <div className="container">
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading system information...</p>
        </div>
      </div>
    );
  }

  if (mood || !bits) {
    return (
      <div className="container">
        <div className="error-state">
          <div className="error-icon">!</div>
          <p className="error-text">{mood || "Failed to load system information"}</p>
        </div>
      </div>
    );
  }

  if (["settings", "subscription", "monitor"].includes(currentPage)) {
    return (
      <main className={`container settings-page ${isExiting ? "page-exiting" : ""}`}>
        <SettingsPage
          currentPage={currentPage}
          navigateTo={navigateTo}
          language={language}
          setLanguage={setLanguage}
          isDevBuild={isDevBuild}
          checkoutUrl={checkoutUrl}
          devUnlockAllowed={devUnlockAllowed}
          devUnlocked={devUnlocked}
          setDevUnlocked={setDevUnlocked}
          entitlements={entitlements}
          setEntitlements={setEntitlements}
          entitlementsLoading={entitlementsLoading}
          isSubscribed={isSubscribed}
          effectiveSubscribed={effectiveSubscribed}
          theme={theme}
          setTheme={setTheme}
          saveTheme={saveTheme}
          setSaveTheme={setSaveTheme}
          systemHostname={bits.system.hostname}
          monitorEnabled={monitorEnabled}
          setMonitorEnabled={setMonitorEnabled}
          monitorSensitivity={monitorSensitivity}
          setMonitorSensitivity={setMonitorSensitivity}
          incidents={incidents}
          samples={samples}
          deleteIncident={deleteIncident}
          clearIncidents={clearIncidents}
        />
      </main>
    );
  }

  return (
    <main className={`container ${isExiting ? "page-exiting" : ""}`}>
      <OverviewPage
        bits={bits}
        language={language}
        entitlementsLoading={entitlementsLoading}
        effectiveSubscribed={effectiveSubscribed}
        navigateTo={navigateTo}
      />
    </main>
  );
}

export default App;