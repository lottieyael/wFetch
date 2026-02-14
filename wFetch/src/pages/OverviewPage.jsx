import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { t } from "../translations";
import {
  FadingText,
  InfoCard,
  InfoRow,
  ProgressBar,
} from "../components/InfoComponents";

export function OverviewPage({
  bits,
  language,
  entitlementsLoading,
  effectiveSubscribed,
  navigateTo,
}) {
  const [story, setStory] = useState(null);
  const [storyBusy, setStoryBusy] = useState(false);
  const [storyOops, setStoryOops] = useState(null);
  const [pauseUntil, setPauseUntil] = useState(null);
  const [ticks, setTicks] = useState(0);
  const [analyzePercent, setAnalyzePercent] = useState(0);

  const [dropdownOpen, setDropdownOpen] = useState(false);

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

  const { cpu, memory, system, gpus, disk, network } = bits;
  const memoryUsed = memory.total_gb - memory.free_gb;
  const memorySlice = memory.total_gb > 0 ? (memoryUsed / memory.total_gb) * 100 : 0;
  const diskUsed = disk.total_gb - disk.free_gb;
  const diskSlice = disk.total_gb > 0 ? (diskUsed / disk.total_gb) * 100 : 0;

  return (
    <>
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
                onClick={() => {
                  navigateTo("settings");
                  setDropdownOpen(false);
                }}
              >
                Settings
              </button>
              <button
                className="settings-dropdown-item"
                onClick={() => {
                  navigateTo("subscription");
                  setDropdownOpen(false);
                }}
              >
                Subscription
              </button>
              <button
                className="settings-dropdown-item"
                onClick={() => {
                  navigateTo("monitor");
                  setDropdownOpen(false);
                }}
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
              const paragraphs = story.split("\n").filter((p) => p.trim());
              let currentDelay = 0;
              const step = 8;

              return paragraphs.map((paragraph, index) => {
                const delay = currentDelay;
                currentDelay += paragraph.length * step + 200;
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
              <div className="os-name">{bits.os.split(" (Build")[0]}</div>
              <div className="os-meta-info">
                <div className="os-badge architecture">
                  <span className="badge-label">{t("labels.architecture", language)}</span>
                  <span className="badge-value">{cpu.architecture}</span>
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
          <InfoRow label={t("labels.model", language)} value={cpu.name} />
          <InfoRow label={t("labels.architecture", language)} value={cpu.architecture} />
          <InfoRow label={t("labels.cores", language)} value={cpu.processors} />
        </InfoCard>

        <InfoCard title={t("cards.memory", language)}>
          <div className="metric-display">
            <div className="metric-value">{memoryUsed.toFixed(1)} GB</div>
            <div className="metric-total">
              {t("labels.of", language)} {memory.total_gb.toFixed(1)} GB
            </div>
          </div>
          <ProgressBar percent={memorySlice} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">
              {t("labels.free", language)}: {memory.free_gb.toFixed(1)} GB
            </span>
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
            <div className="metric-total">
              {t("labels.of", language)} {disk.total_gb.toFixed(1)} GB
            </div>
          </div>
          <ProgressBar percent={diskSlice} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">
              {t("labels.free", language)}: {disk.free_gb.toFixed(1)} GB
            </span>
            <span className="metric-percent">{diskSlice.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title={t("cards.network", language)}>
          {network.length > 0 ? (
            network.map((adapter, index) => (
              <InfoRow
                key={index}
                label={`${t("labels.adapter", language)} ${index + 1}`}
                value={adapter}
              />
            ))
          ) : (
            <InfoRow label="" value={t("labels.noAdapters", language)} />
          )}
        </InfoCard>
      </div>
    </>
  );
}
