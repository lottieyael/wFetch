import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  const [bits, setBits] = useState(null);
  const [waiting, setWaiting] = useState(true);
  const [mood, setMood] = useState(null);
  const [story, setStory] = useState(null);
  const [storyBusy, setStoryBusy] = useState(false);
  const [storyOops, setStoryOops] = useState(null);
  const [pauseUntil, setPauseUntil] = useState(null);
  const [ticks, setTicks] = useState(0);
  const memoryIntervalStarted = useRef(false);

  useEffect(() => {
    const grab = async () => {
      try {
        const info = await invoke("get_system_info");
        setBits(info);
      } catch (err) {
        setMood(err?.message || "Failed to load system information");
      } finally {
        setWaiting(false);
      }
    };
    grab();
  }, []);

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

  const nudgeStory = async () => {
    if (!bits || ticks > 0) return;
    setStoryBusy(true);
    setStoryOops(null);
    setStory(null);
    try {
      const reply = await invoke("send_to_ai", { systemInfo: bits });
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

  return (
    <main className="container">
      <header className="header">
        <div className="header-content">
          <h1 className="app-title">wFetch</h1>
          <p className="app-subtitle">System Overview</p>
        </div>
        <button className="ai-button" onClick={nudgeStory} disabled={storyBusy || ticks > 0}>
          {storyBusy ? "Analyzing..." : ticks > 0 ? `Cooldown: ${ticks}s` : "Analyze with AI"}
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
          <div className="ai-content">{story}</div>
        </div>
      )}

      <div className="info-grid">
        <InfoCard title="Operating System">
          <InfoRow label="Version" value={os} />
        </InfoCard>

        <InfoCard title="Processor">
          <InfoRow label="Model" value={cpu.name} />
          <InfoRow label="Architecture" value={cpu.architecture} />
          <InfoRow label="Cores" value={cpu.processors} />
        </InfoCard>

        <InfoCard title="Memory">
          <div className="metric-display">
            <div className="metric-value">{memoryUsed.toFixed(1)} GB</div>
            <div className="metric-total">of {memory.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={memorySlice} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">Free: {memory.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{memorySlice.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title="System">
          <InfoRow label="Hostname" value={system.hostname} />
          <InfoRow label="User" value={system.username} />
        </InfoCard>

        <InfoCard title="Graphics">
          {gpus.length > 0 ? (
            gpus.map((gpu, index) => (
              <InfoRow
                key={index}
                label={`GPU ${index + 1}`}
                value={gpu.name}
                extra={gpu.vram_mb > 0 ? `${gpu.vram_mb} MB VRAM` : null}
              />
            ))
          ) : (
            <InfoRow label="" value="No GPUs detected" />
          )}
        </InfoCard>

        <InfoCard title="Storage">
          <div className="metric-display">
            <div className="metric-value">{diskUsed.toFixed(1)} GB</div>
            <div className="metric-total">of {disk.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={diskSlice} color="purple" />
          <div className="metric-details">
            <span className="metric-detail">Free: {disk.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{diskSlice.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title="Network">
          {network.length > 0 ? (
            network.map((adapter, index) => <InfoRow key={index} label={`Adapter ${index + 1}`} value={adapter} />)
          ) : (
            <InfoRow label="" value="No active adapters" />
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