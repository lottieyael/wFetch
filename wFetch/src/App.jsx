import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
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
  const [theme, setTheme] = useState("system");
  const [language, setLanguage] = useState(() => localStorage.getItem("language") || "en");
  const [isExiting, setIsExiting] = useState(false);
  const memoryIntervalStarted = useRef(false);

  useEffect(() => {
    localStorage.setItem("language", language);
  }, [language]);

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
    applyTheme(theme);
  }, [theme]);

  
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

  if (currentPage === "settings") {
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
            <h1 className="app-title">{t("settings.title", language)}</h1>
            <p className="app-subtitle">{t("settings.subtitle", language)}</p>
          </div>
          
          <div style={{ width: "110px" }}></div>
        </header>

        <div className="info-grid settings-grid">
          <InfoCard title="Application">
            <InfoRow label={t("settings.version", language)} value="1.3.2" />
          </InfoCard>

          <InfoCard title={t("settings.theme", language)}>
            <div className="setting-row">
              <div className="setting-control">
                <button
                  type="button"
                  className={`pill-toggle ${theme === "system" ? "pill-toggle-active" : ""}`}
                  onClick={() => setTheme("system")}
                >
                  Cosmic Purple
                </button>
                <button
                  type="button"
                  className={`pill-toggle ${theme === "light" ? "pill-toggle-active" : ""}`}
                  onClick={() => setTheme("light")}
                >
                  Fresh Air
                </button>
                <button
                  type="button"
                  className={`pill-toggle ${theme === "dark" ? "pill-toggle-active" : ""}`}
                  onClick={() => setTheme("dark")}
                >
                  Inferno Red
                </button>
              </div>
            </div>
          </InfoCard>

          <InfoCard title={t("settings.language", language)}>
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
        </div>
      </main>
    );
  }

  return (
    <main className={`container ${isExiting ? "page-exiting" : ""}`}>
      <header className="header">
        <button
          type="button"
          className="settings-button"
          onClick={() => navigateTo("settings")}
          aria-label="Open settings"
        >
          <span className="settings-icon">⚙️</span>
          <span className="settings-label">Settings</span>
        </button>
        <div className="header-content">
          <h1 className="app-title">{t("app.title", language)}</h1>
          <p className="app-subtitle">{t("app.subtitle", language)}</p>
        </div>
        <button
          className="ai-button"
          onClick={nudgeStory}
          disabled={storyBusy || ticks > 0}
        >
          {storyBusy
            ? t("app.analyzing", language, { percent: analyzePercent })
            : ticks > 0
            ? t("app.cooldown", language, { seconds: ticks })
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
            {story.split('\n').map((paragraph, index) => (
              paragraph.trim() ? <p key={index}>{paragraph}</p> : null
            ))}
          </div>
        </div>
      )}

      <div className="info-grid">
        <InfoCard title={t("cards.os", language)}>
          <InfoRow label="Version" value={bits.os} />
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
              <InfoRow
                key={index}
                label={`${t("labels.gpu", language)} ${index + 1}`}
                value={gpu.name}
                extra={gpu.vram_mb > 0 ? `${gpu.vram_mb} MB ${t("labels.vram", language)}` : null}
              />
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

function InfoCard({ title, children }) {
  return (
    <div className="info-card">
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

export default App;