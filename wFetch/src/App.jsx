import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import "./App.css";
import { t } from "./translations";

function App() {
  const [bits, setBits] = useState(null);
  const [waiting, setWaiting] = useState(true);
  const [mood, setMood] = useState(null);
  const [story, setStory] = useState(null);
  const [storyBusy, setStoryBusy] = useState(false);
  const [storyOops, setStoryOops] = useState(null);
  const [pauseUntil, setPauseUntil] = useState(null);
  const [ticks, setTicks] = useState(0);
  const [analyzePercent, setAnalyzePercent] = useState(0);
  const [currentPage, setCurrentPage] = useState("overview");
  const [saveTheme, setSaveTheme] = useState(() => localStorage.getItem("saveTheme") === "true");
  const [theme, setTheme] = useState(() => {
    const shouldSave = localStorage.getItem("saveTheme") === "true";
    return shouldSave ? (localStorage.getItem("theme") || "system") : "system";
  });
  const [language, setLanguage] = useState(() => localStorage.getItem("language") || "en");
  const [isExiting, setIsExiting] = useState(false);
  const [entitlements, setEntitlements] = useState(null);
  const [entitlementsLoading, setEntitlementsLoading] = useState(true);
  const [licenseKey, setLicenseKey] = useState("");
  const [licenseBusy, setLicenseBusy] = useState(false);
  const [licenseOops, setLicenseOops] = useState(null);
  const [licenseOk, setLicenseOk] = useState(null);
  const [monitorEnabled, setMonitorEnabled] = useState(() => localStorage.getItem("monitorEnabled") === "true");
  const [monitorSensitivity, setMonitorSensitivity] = useState(() => parseInt(localStorage.getItem("monitorSensitivity") || "85", 10));
  const [incidents, setIncidents] = useState([]);
  const memoryIntervalStarted = useRef(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [settingsSection, setSettingsSection] = useState(null);

  const [netDiagBusy, setNetDiagBusy] = useState(false);
  const [netDiagOops, setNetDiagOops] = useState(null);
  const [netDiagResult, setNetDiagResult] = useState(null);

  const checkoutUrl = import.meta.env.VITE_LEMONSQUEEZY_CHECKOUT_URL || "";
  const devUnlockAllowed = import.meta.env.DEV;
  const isDevBuild = import.meta.env.TAURI_ENV_DEBUG === "true" || import.meta.env.DEV;
  const [devUnlocked, setDevUnlocked] = useState(() => {
    if (!devUnlockAllowed) return false;
    return localStorage.getItem("devUnlocked") === "true";
  });
  const isSubscribed = !!entitlements?.active;
  const effectiveSubscribed = devUnlocked || isSubscribed;

  useEffect(() => {
    localStorage.setItem("language", language);
  }, [language]);

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
    const grab = async () => {
      try {
        // FAST PATH: Show immediately
        const fastInfo = await invoke("get_fast_system_info");
        setBits({
          ...fastInfo,
          gpus: [],
          network: [],
        });
        setWaiting(false);

        // SLOW PATH: Load in parallel, non-blocking
        const [gpuResult, networkResult] = await Promise.allSettled([
          invoke("get_gpu_info"),
          invoke("get_network_info"),
        ]);

        // Update state with slow data when ready
        setBits(prev => {
          if (!prev) return prev;
          return {
            ...prev,
            gpus: gpuResult.status === "fulfilled" ? gpuResult.value : [],
            network: networkResult.status === "fulfilled" ? networkResult.value : [],
          };
        });
      } catch (err) {
        setMood(err?.message || "Failed to load system information");
        setWaiting(false);
      }
    };
    grab();
  }, []);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const cached = await invoke("ls_get_entitlements");
        if (!alive) return;
        setEntitlements(cached);

        try {
          const fresh = await invoke("ls_refresh_entitlements");
          if (!alive) return;
          setEntitlements(fresh);
        } catch {
          // If refresh fails (offline), keep cached entitlements.
        }
      } catch {
        if (!alive) return;
        setEntitlements({ active: false });
      } finally {
        if (!alive) return;
        setEntitlementsLoading(false);
      }
    };
    load();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    applyTheme(effectiveSubscribed ? theme : "system");
  }, [theme, effectiveSubscribed]);

  useEffect(() => {
    localStorage.setItem("monitorEnabled", monitorEnabled.toString());
    invoke("set_monitor_state", { enabled: monitorEnabled }).catch(() => {});
  }, [monitorEnabled]);

  useEffect(() => {
    localStorage.setItem("monitorSensitivity", monitorSensitivity.toString());
    invoke("set_monitor_sensitivity", { threshold: monitorSensitivity }).catch(() => {});
  }, [monitorSensitivity]);

  useEffect(() => {
    if (!monitorEnabled) return;
    
    invoke("get_monitor_incidents").then(setIncidents).catch(() => {});
    
    const unlistenPromise = listen("monitor-incident", (event) => {
      setIncidents(prev => [event.payload, ...prev].slice(0, 10));
    });
    
    return () => {
      unlistenPromise.then(unlisten => unlisten());
    };
  }, [monitorEnabled]);

  useEffect(() => {
    if (!effectiveSubscribed && theme !== "system") {
      setTheme("system");
    }
  }, [effectiveSubscribed]);

  
  const applyTheme = (themeName) => {
    const themes = {
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

    const selectedTheme = themes[themeName] || themes.system;
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
  };
  

  useEffect(() => {
    if (waiting || !bits || memoryIntervalStarted.current) return;
    
    memoryIntervalStarted.current = true;
    
    const updateMemory = async () => {
      try {
        const memoryInfo = await invoke("get_memory_info");
        setBits(prevBits => {
          if (!prevBits) return prevBits;
          return {
            ...prevBits,
            memory: memoryInfo
          };
        });
      } catch (err) {
        console.error("Failed to update memory info:", err);
      }
    };

    // Run immediately, then every 5 seconds
    updateMemory();
    const interval = setInterval(updateMemory, 5000);
    
    return () => {
      clearInterval(interval);
      memoryIntervalStarted.current = false;
    };
  }, [waiting]);

  useEffect(() => {
    if (!pauseUntil) {
      setTicks(0);
      return;
    }
    const refresh = () => {
      const now = Date.now();
      const left = Math.max(0, Math.ceil((pauseUntil - now) / 1000));
      setTicks(left);
      if (left <= 0) {
        setPauseUntil(null);
      }
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => clearInterval(timer);
  }, [pauseUntil]);

  useEffect(() => {
    if (!storyBusy) {
      setAnalyzePercent(0);
      return;
    }

    setAnalyzePercent(0);
    const timer = setInterval(() => {
      setAnalyzePercent((prev) => {
        if (prev >= 99) {
          // hover just under 100% until the request finishes
          return 99;
        }
        const increment = 1 + Math.floor(Math.random() * 5);
        return Math.min(99, prev + increment);
      });
    }, 200);

    return () => clearInterval(timer);
  }, [storyBusy]);

  const nudgeStory = async () => {
    if (!bits || ticks > 0) return;

    if (entitlementsLoading || !effectiveSubscribed) {
      setStoryOops(t("app.analyzeLocked", language));
      return;
    }

    setStoryBusy(true);
    setStoryOops(null);
    setStory(null);
    try {
      const reply = await invoke("send_to_ai", { systemInfo: bits, lang: language });
      setStory(reply);
      setPauseUntil(Date.now() + 60000);
    } catch (err) {
      const words =
        typeof err === "string"
          ? err
          : err?.message || err?.toString() || "Failed to get AI analysis";
      setStoryOops(words);
      setPauseUntil(Date.now() + 60000);
    } finally {
      setStoryBusy(false);
    }
  };

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

  const { os, cpu, memory, system, gpus, disk, network } = bits;
  const memoryUsed = memory.total_gb - memory.free_gb;
  const memorySlice = memory.total_gb > 0 ? (memoryUsed / memory.total_gb) * 100 : 0;
  const diskUsed = disk.total_gb - disk.free_gb;
  const diskSlice = disk.total_gb > 0 ? (diskUsed / disk.total_gb) * 100 : 0;

  if (["settings", "subscription", "monitor"].includes(currentPage)) {
    const activateLicense = async () => {
      const trimmed = licenseKey.trim();
      if (!trimmed) return;

      if (devUnlockAllowed && trimmed === "bestMilioSupportEver") {
        localStorage.setItem("devUnlocked", "true");
        setDevUnlocked(true);
        setLicenseKey("");
        setLicenseOk("Developer unlock cheat enabled (dev ver. only). ");
        setLicenseOops(null);
        return;
      }

      if (devUnlockAllowed && trimmed === "worstMilioSupportEver") {
        localStorage.removeItem("devUnlocked");
        setDevUnlocked(false);
        setLicenseKey("");
        setLicenseOk("Developer unlock cheat disabled (dev ver. only).");
        setLicenseOops(null);
        return;
      }

      setLicenseBusy(true);
      setLicenseOops(null);
      setLicenseOk(null);
      try {
        const result = await invoke("ls_activate_license", {
          license_key: trimmed,
          instance_name: system.hostname,
        });
        setEntitlements(result);
        setLicenseKey("");
        setLicenseOk(t("settings.subscription.activated", language));
      } catch (err) {
        const msg =
          typeof err === "string"
            ? err
            : err?.message || err?.toString() || t("settings.subscription.activationFailed", language);
        setLicenseOops(msg);
      } finally {
        setLicenseBusy(false);
      }
    };

    const refreshLicense = async () => {
      setLicenseBusy(true);
      setLicenseOops(null);
      setLicenseOk(null);
      try {
        const result = await invoke("ls_refresh_entitlements");
        setEntitlements(result);
        setLicenseOk(t("settings.subscription.refreshed", language));
      } catch (err) {
        const msg =
          typeof err === "string"
            ? err
            : err?.message || err?.toString() || t("settings.subscription.refreshFailed", language);
        setLicenseOops(msg);
      } finally {
        setLicenseBusy(false);
      }
    };

    const deactivateLicense = async () => {
      if (devUnlocked) {
        localStorage.removeItem("devUnlocked");
        setDevUnlocked(false);
        setLicenseOk("Developer unlock disabled.");
        setLicenseOops(null);
        return;
      }

      setLicenseBusy(true);
      setLicenseOops(null);
      setLicenseOk(null);
      try {
        await invoke("ls_deactivate_license");
        setEntitlements({ active: false });
        setLicenseOk(t("settings.subscription.deactivated", language));
      } catch (err) {
        const msg =
          typeof err === "string"
            ? err
            : err?.message || err?.toString() || t("settings.subscription.deactivationFailed", language);
        setLicenseOops(msg);
      } finally {
        setLicenseBusy(false);
      }
    };

    const openCheckout = async () => {
      if (!checkoutUrl) {
        setLicenseOops(t("settings.subscription.missingCheckoutUrl", language));
        return;
      }
      try {
        await openUrl(checkoutUrl);
      } catch {
        setLicenseOops(t("settings.subscription.openCheckoutFailed", language));
      }
    };

    let pageTitle = t("settings.title", language);
    if (currentPage === "subscription") pageTitle = t("settings.subscription.title", language);
    if (currentPage === "monitor") pageTitle = t("settings.monitor.title", language);

    return (
      <main className={`container settings-page ${isExiting ? "page-exiting" : ""}`}>
        <header className="header">
          <button
            type="button"
            className="back-button"
            onClick={() => navigateTo("overview")}
          >
            {t("settings.backButton", language)}
          </button>
          
          <div className="header-content">
            <h1 className="app-title">{pageTitle}</h1>
            {/*<p className="app-subtitle">{t("settings.subtitle", language)}</p>*/}
          </div>
          
          <div style={{ width: "110px" }}></div>
        </header>

        <div className={`info-grid settings-grid ${currentPage !== "settings" ? "single-card-page" : ""}`}>
          {currentPage === "subscription" && (
            <InfoCard id="settings-subscription" title={t("settings.subscription.title", language)}>
              <div className="subscription-status">
                <div className={`status-pill ${isSubscribed ? "active" : "inactive"}`}>
                  {entitlementsLoading
                    ? t("settings.subscription.loading", language)
                    : isSubscribed
                    ? t("settings.subscription.statusActive", language)
                    : t("settings.subscription.statusInactive", language)}
                </div>

                {entitlements?.license_key_last4 && (
                  <div className="status-meta">
                    {t("settings.subscription.licenseEnding", language, {
                      last4: entitlements.license_key_last4,
                    })}
                  </div>
                )}

                {entitlements?.customer_email && <div className="status-meta">{entitlements.customer_email}</div>}
                {entitlements?.expires_at && (
                  <div className="status-meta">
                    {t("settings.subscription.expires", language, { date: entitlements.expires_at })}
                  </div>
                )}
              </div>

              {licenseOops && <div className="subscription-message error">{licenseOops}</div>}
              {licenseOk && <div className="subscription-message ok">{licenseOk}</div>}

              {!isSubscribed ? (
                <div className="license-row">
                  <input
                    className="license-input"
                    value={licenseKey}
                    onChange={(e) => setLicenseKey(e.target.value)}
                    placeholder={t("settings.subscription.licensePlaceholder", language)}
                    disabled={licenseBusy}
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                  />
                </div>
              ) : null}

              <div className="license-actions">
                {!isSubscribed ? (
                  <>
                    <button
                      type="button"
                      className="pill-toggle pill-toggle-active pill-toggle-buy"
                      disabled={licenseBusy}
                      onClick={openCheckout}
                    >
                      {t("settings.subscription.buy", language)}
                    </button>
                    <button
                      type="button"
                      className="pill-toggle pill-toggle-dark"
                      disabled={licenseBusy || !licenseKey.trim()}
                      onClick={activateLicense}
                    >
                      {t("settings.subscription.activate", language)}
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      className="pill-toggle"
                      disabled={licenseBusy}
                      onClick={refreshLicense}
                    >
                      {t("settings.subscription.refresh", language)}
                    </button>
                    <button
                      type="button"
                      className="pill-toggle"
                      disabled={licenseBusy}
                      onClick={deactivateLicense}
                    >
                      {t("settings.subscription.deactivate", language)}
                    </button>
                  </>
                )}
              </div>

              <div className="subscription-help">{t("settings.subscription.help", language)}</div>
            </InfoCard>
          )}

          {currentPage === "monitor" && (
            <InfoCard id="settings-monitor" title={t("settings.monitor.title", language)}>
              <div className="setting-row">
                <div className="setting-label">
                  {t("settings.monitor.enable", language)}
                  <span className="setting-help">{t("settings.monitor.enableHelp", language)}</span>
                </div>
                <div className="setting-control">
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={monitorEnabled}
                      onChange={(e) => setMonitorEnabled(e.target.checked)}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
              
              {monitorEnabled && (
                <div className="setting-row">
                  <div className="setting-label">
                    {t("settings.monitor.sensitivity", language)} ({monitorSensitivity}%)
                    <span className="setting-help">{t("settings.monitor.sensitivityHelp", language)}</span>
                  </div>
                  <div className="setting-control" style={{ width: "50%" }}>
                    <input 
                      type="range" 
                      min="50" 
                      max="99" 
                      value={monitorSensitivity} 
                      onChange={(e) => setMonitorSensitivity(parseInt(e.target.value, 10))}
                      className="sensitivity-slider"
                      style={{ width: "100%" }}
                    />
                  </div>
                </div>
              )}

              {monitorEnabled && incidents.length > 0 && (
                <div className="incidents-list">
                  <div className="setting-label" style={{marginBottom: '10px'}}>{t("settings.monitor.viewIncidents", language)}</div>
                  {incidents.map(inc => (
                    <div key={inc.id} className="incident-item">
                      <div className="incident-header">
                        <span>{new Date(inc.timestamp * 1000).toLocaleTimeString()}</span>
                        <span className="incident-cpu">{inc.total_cpu.toFixed(1)}% CPU</span>
                      </div>
                      <div className="incident-processes">
                        {inc.processes.slice(0, 3).map(p => (
                          <div key={p.pid} className="incident-process">
                            <span>{p.name}</span>
                            <span>{p.cpu_percent.toFixed(1)}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {monitorEnabled && incidents.length === 0 && (
                <div className="setting-row">
                  <div className="setting-help">{t("settings.monitor.noIncidents", language)}</div>
                </div>
              )}
            </InfoCard>
          )}

          {currentPage === "settings" && (
            <>
              <InfoCard id="settings-application" title="Application">
                <InfoRow label={t("settings.version", language)} value="1.5.2" />
                <InfoRow
                  label={t("settings.buildMode", language)}
                  value={isDevBuild ? t("settings.buildModeDev", language) : t("settings.buildModeRelease", language)}
                />
              </InfoCard>

              <InfoCard id="settings-admin-network" title="Admin: Network Diagnostics">
                <div className="subscription-help" style={{ marginBottom: "10px" }}>
                  Runs Windows remote diagnostics across discovered LAN hosts and exports an Excel report to your Desktop.
                  Remote access requires WMI/CIM over DCOM permissions and may fail on locked-down machines.
                </div>

                {netDiagOops && <div className="subscription-message error">{netDiagOops}</div>}
                {netDiagResult && (
                  <div className="subscription-message ok" style={{ whiteSpace: "pre-wrap" }}>
                    Exported: {netDiagResult.output_path}
                    {"\n"}Discovered: {netDiagResult.discovered_hosts} | Scanned: {netDiagResult.scanned_hosts}
                    {"\n"}Succeeded: {netDiagResult.succeeded} | Failed: {netDiagResult.failed}
                  </div>
                )}

                <div className="license-actions">
                  <button
                    type="button"
                    className="pill-toggle"
                    disabled={netDiagBusy}
                    onClick={async () => {
                      setNetDiagBusy(true);
                      setNetDiagOops(null);
                      setNetDiagResult(null);
                      try {
                        const result = await invoke("scan_network_and_export_excel", {
                          options: {
                            max_hosts: 128,
                            include_neighbors: true,
                            ping_sweep: true,
                            per_host_timeout_ms: 8000,
                            concurrency: 16,
                          },
                        });
                        setNetDiagResult(result);
                      } catch (err) {
                        const msg =
                          typeof err === "string"
                            ? err
                            : err?.message || err?.toString() || "Network diagnostics failed.";
                        setNetDiagOops(msg);
                      } finally {
                        setNetDiagBusy(false);
                      }
                    }}
                  >
                    {netDiagBusy ? "Scanning…" : "Scan network & export Excel"}
                  </button>
                </div>
              </InfoCard>

              <InfoCard id="settings-theme" title={t("settings.theme", language)}>
                <div className="setting-row">
                  <div className="setting-control">
                    <button
                      type="button"
                      className={`pill-toggle ${theme === "system" ? "pill-toggle-active" : ""}`}
                      onClick={() => setTheme("system")}
                    >
                      {t("settings.themes.system", language)}
                    </button>
                    <button
                      type="button"
                      className={`pill-toggle ${theme === "light" ? "pill-toggle-active" : ""}`}
                      onClick={() => setTheme("light")}
                      disabled={!effectiveSubscribed}
                    >
                      {t("settings.themes.light", language)}{!effectiveSubscribed ? " 🔒" : ""}
                    </button>
                    <button
                      type="button"
                      className={`pill-toggle ${theme === "dark" ? "pill-toggle-active" : ""}`}
                      onClick={() => setTheme("dark")}
                      disabled={!effectiveSubscribed}
                    >
                      {t("settings.themes.dark", language)}{!effectiveSubscribed ? " 🔒" : ""}
                    </button>
                    <button
                      type="button"
                      className={`pill-toggle ${theme === "cherry" ? "pill-toggle-active" : ""}`}
                      onClick={() => setTheme("cherry")}
                      disabled={!effectiveSubscribed}
                    >
                      {t("settings.themes.cherry", language)}{!effectiveSubscribed ? " 🔒" : ""}
                    </button>
                    <button
                      type="button"
                      className={`pill-toggle ${theme === "midnight" ? "pill-toggle-active" : ""}`}
                      onClick={() => setTheme("midnight")}
                      disabled={!effectiveSubscribed}
                    >
                      {t("settings.themes.midnight", language)}{!effectiveSubscribed ? " 🔒" : ""}
                    </button>
                  </div>
                </div>
                <div className="setting-row">
                  <div className="setting-label">
                    {t("settings.saveThemePreference", language)}
                    <span className="setting-help">{t("settings.saveThemeHelp", language)}</span>
                  </div>
                  <div className="setting-control">
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={saveTheme}
                        onChange={(e) => setSaveTheme(e.target.checked)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>
              </InfoCard>

              <InfoCard id="settings-language" title={t("settings.language", language)}>
                <div className="setting-row">
                  <div className="setting-label">
                    {t("settings.language", language)}
                    <span className="setting-help">{t("settings.languageHelp", language)}</span>
                  </div>
                  <div className="setting-control">
                    <select
                      className="setting-select"
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                    >
                      <option value="en">English</option>
                      <option value="es">Español</option>
                      <option value="fr">Français</option>
                      <option value="hu">Magyar</option>
                      <option value="zh">中文</option>
                    </select>
                  </div>
                </div>
              </InfoCard>
            </>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className={`container ${isExiting ? "page-exiting" : ""}`}>
      <header className="header">
        <div className="settings-dropdown-container">
          <button
            type="button"
            className="settings-button"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            aria-label="Open settings menu"
          >
            <span className="settings-label">Extras</span>
          </button>
          {dropdownOpen && (
            <div className="settings-dropdown-menu">
              <button 
                className="settings-dropdown-item"
                onClick={() => { navigateTo("settings"); setDropdownOpen(false); }}
              >
                Settings
              </button>
              <button 
                className="settings-dropdown-item"
                onClick={() => { navigateTo("subscription"); setDropdownOpen(false); }}
              >
                Subscription
              </button>
              <button 
                className="settings-dropdown-item"
                onClick={() => { navigateTo("monitor"); setDropdownOpen(false); }}
              >
                Background Monitor
              </button>
            </div>
          )}
        </div>
        <div className="header-content">
          <h1 className="app-title">{t("app.title", language)}</h1>
          <p className="app-subtitle">{t("app.subtitle", language)}</p>
        </div>
        <button
          className="ai-button"
          onClick={nudgeStory}
          disabled={storyBusy || ticks > 0 || entitlementsLoading || !effectiveSubscribed}
        >
          {storyBusy
            ? t("app.analyzing", language, { percent: analyzePercent })
            : ticks > 0
            ? t("app.cooldown", language, { seconds: ticks })
            : entitlementsLoading || !effectiveSubscribed
            ? t("app.analyzeLocked", language)
            : t("app.analyzeButton", language)}
        </button>
      </header>

      {storyOops && (
        <div className="ai-response error">
          <h3>AI Analysis Error</h3>
          <p>{storyOops}</p>
        </div>
      )}

      {story && (
        <div className="ai-response">
          <h3>AI Analysis</h3>
          <div className="ai-content">
            {(() => {
              const paragraphs = story.split('\n').filter(p => p.trim());
              let currentDelay = 0;
              const step = 8;
              
              return paragraphs.map((paragraph, index) => {
                const delay = currentDelay;
                currentDelay += (paragraph.length * step) + 200;
                return (
                  <p key={index}>
                    <FadingText text={paragraph} startDelay={delay} step={step} />
                  </p>
                );
              });
            })()}
          </div>
        </div>
      )}

      <div className="info-grid">
        <InfoCard title={t("cards.os", language)}>
        <div className="os-display">
          <div className="os-info">
            <div className="os-name">{bits.os.split(' (Build')[0]}</div>
            <div className="os-meta-info">
              <div className="os-badge architecture">
                <span className="badge-label">{t("labels.architecture", language)}</span>
                <span className="badge-value">{bits.cpu.architecture}</span>
              </div>
              <div className="os-badge">
                <span className="badge-label">Build</span>
                <span className="badge-value">{bits.os.match(/Build (\d+)/)?.[1] || "Unknown"}</span>
              </div>
            </div>
          </div>
        </div>
        </InfoCard>

        <InfoCard title={t("cards.processor", language)}>
          <InfoRow label={t("labels.model", language)} value={bits.cpu.name} />
          <InfoRow label={t("labels.architecture", language)} value={bits.cpu.architecture} />
          <InfoRow label={t("labels.cores", language)} value={bits.cpu.processors} />
        </InfoCard>

        <InfoCard title={t("cards.memory", language)}>
          <div className="metric-display">
            <div className="metric-value">{memoryUsed.toFixed(1)} GB</div>
            <div className="metric-total">{t("labels.of", language)} {memory.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={memorySlice} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">{t("labels.free", language)}: {memory.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{memorySlice.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title={t("cards.system", language)}>
          <InfoRow label={t("labels.hostname", language)} value={system.hostname} />
          <InfoRow label={t("labels.user", language)} value={system.username} />
        </InfoCard>

        <InfoCard title={t("cards.graphics", language)}>
          {gpus.length > 0 ? (
            gpus.map((gpu, index) => (
              <div key={index} className="gpu-display">
                <div className="gpu-info">
                  <div className="gpu-name">{gpu.name}</div>
                  <div className="gpu-meta-info">
                    <div className="gpu-badge manufacturer">
                      <span className="badge-label">Manufacturer</span>
                      <span className="badge-value">{gpu.manufacturer}</span>
                    </div>
                    {gpu.vram_mb > 0 && (
                      <div className="gpu-badge">
                        <span className="badge-label">VRAM</span>
                        <span className="badge-value">{gpu.vram_mb} MB</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <InfoRow label="" value={t("labels.noGpus", language)} />
          )}
        </InfoCard>

        <InfoCard title={t("cards.storage", language)}>
          <div className="metric-display">
            <div className="metric-value">{diskUsed.toFixed(1)} GB</div>
            <div className="metric-total">{t("labels.of", language)} {disk.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={diskSlice} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">{t("labels.free", language)}: {disk.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{diskSlice.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title={t("cards.network", language)}>
          {network.length > 0 ? (
            network.map((adapter, index) => <InfoRow key={index} label={`${t("labels.adapter", language)} ${index + 1}`} value={adapter} />)
          ) : (
            <InfoRow label="" value={t("labels.noAdapters", language)} />
          )}
        </InfoCard>
      </div>
    </main>
  );
}

function InfoCard({ title, children, id }) {
  return (
    <div className="info-card" id={id}>
      <div className="card-header">
        <h2 className="card-title">{title}</h2>
      </div>
      <div className="card-content">{children}</div>
    </div>
  );
}

function InfoRow({ label, value, extra }) {
  return (
    <div className="info-item">
      {label && <span className="info-label">{label}</span>}
      <span className="info-value">
        {value}
        {extra && <span className="vram"> ({extra})</span>}
      </span>
    </div>
  );
}

function ProgressBar({ percent, color }) {
  const gradient =
    color === "blue"
      ? "linear-gradient(90deg, #007AFF 0%, #5E5CE6 100%)"
      : "linear-gradient(90deg, #AF52DE 0%, #FF2D55 100%)";

  return (
    <div className="progress-container">
      <div
        className="progress-bar"
        style={{
          width: `${percent}%`,
          background: gradient,
        }}
      >
        <div className="progress-shine"></div>
      </div>
    </div>
  );
}

function FadingText({ text, startDelay = 0, step = 20 }) {
  const chars = Array.from(text);
  return (
    <span className="fading-text" aria-label={text}>
      {chars.map((ch, i) => (
        <span
          key={i}
          className="ai-char"
          style={{ animationDelay: `${startDelay + i * step}ms` }}
        >
          {ch === ' ' ? '\u00A0' : ch}
        </span>
      ))}
    </span>
  );
}

export default App;