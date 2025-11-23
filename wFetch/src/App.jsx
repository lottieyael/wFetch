import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  const [systemInfo, setSystemInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [aiResponse, setAiResponse] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [cooldownEndTime, setCooldownEndTime] = useState(null);
  const [cooldownRemaining, setCooldownRemaining] = useState(0);

  useEffect(() => {
    async function fetchSystemInfo() {
      try {
        const info = await invoke("get_system_info");
        setSystemInfo(info);
      } catch (err) {
        console.error("Failed to fetch system info:", err);
        setError(err.message || "Failed to load system information");
      } finally {
        setLoading(false);
      }
    }
    fetchSystemInfo();
  }, []);

  // Cooldown countdown effect
  useEffect(() => {
    if (!cooldownEndTime) {
      setCooldownRemaining(0);
      return;
    }

    const updateCooldown = () => {
      const now = Date.now();
      const remaining = Math.max(0, Math.ceil((cooldownEndTime - now) / 1000));
      setCooldownRemaining(remaining);

      if (remaining <= 0) {
        setCooldownEndTime(null);
      }
    };

    // Update immediately
    updateCooldown();

    // Update every second
    const interval = setInterval(updateCooldown, 1000);

    return () => clearInterval(interval);
  }, [cooldownEndTime]);

  async function handleSendToAI() {
    if (!systemInfo || cooldownRemaining > 0) return;
    
    setAiLoading(true);
    setAiError(null);
    setAiResponse(null);
    
    try {
      const response = await invoke("send_to_ai", { systemInfo });
      setAiResponse(response);
      // Set cooldown to 1 minute (60 seconds) after request completes
      setCooldownEndTime(Date.now() + 60000);
    } catch (err) {
      console.error("Failed to send to AI:", err);
      // Tauri errors can be strings or objects
      const errorMessage = typeof err === 'string' 
        ? err 
        : err?.message || err?.toString() || "Failed to get AI analysis";
      setAiError(errorMessage);
      // Set cooldown even on error to prevent spam
      setCooldownEndTime(Date.now() + 60000);
    } finally {
      setAiLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="container">
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading system information...</p>
        </div>
      </div>
    );
  }

  if (error || !systemInfo) {
    return (
      <div className="container">
        <div className="error-state">
          <div className="error-icon">!</div>
          <p className="error-text">{error || "Failed to load system information"}</p>
        </div>
      </div>
    );
  }

  const { os, cpu, memory, system, gpus, disk, network } = systemInfo;
  const usedMemory = memory.total_gb - memory.free_gb;
  const memoryPercent = memory.total_gb > 0 ? (usedMemory / memory.total_gb) * 100 : 0;
  const usedDisk = disk.total_gb - disk.free_gb;
  const diskPercent = disk.total_gb > 0 ? (usedDisk / disk.total_gb) * 100 : 0;

  return (
    <main className="container">
      <header className="header">
        <div className="header-content">
          <h1 className="app-title">wFetch</h1>
          <p className="app-subtitle">System Overview</p>
        </div>
        <button 
          className="ai-button"
          onClick={handleSendToAI}
          disabled={aiLoading || cooldownRemaining > 0}
        >
          {aiLoading 
            ? "Analyzing..." 
            : cooldownRemaining > 0 
            ? `Cooldown: ${cooldownRemaining}s`
            : "Analyze with AI"}
        </button>
      </header>

      {aiError && (
        <div className="ai-response error">
          <h3>AI Analysis Error</h3>
          <p>{aiError}</p>
        </div>
      )}

      {aiResponse && (
        <div className="ai-response">
          <h3>AI Analysis</h3>
          <div className="ai-content">{aiResponse}</div>
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
            <div className="metric-value">{usedMemory.toFixed(1)} GB</div>
            <div className="metric-total">of {memory.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={memoryPercent} color="blue" />
          <div className="metric-details">
            <span className="metric-detail">Free: {memory.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{memoryPercent.toFixed(1)}%</span>
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
            <div className="metric-value">{usedDisk.toFixed(1)} GB</div>
            <div className="metric-total">of {disk.total_gb.toFixed(1)} GB</div>
          </div>
          <ProgressBar percent={diskPercent} color="purple" />
          <div className="metric-details">
            <span className="metric-detail">Free: {disk.free_gb.toFixed(1)} GB</span>
            <span className="metric-percent">{diskPercent.toFixed(1)}%</span>
          </div>
        </InfoCard>

        <InfoCard title="Network">
          {network.length > 0 ? (
            network.map((adapter, index) => (
              <InfoRow 
                key={index}
                label={`Adapter ${index + 1}`}
                value={adapter}
              />
            ))
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
  const gradient = color === 'blue' 
    ? 'linear-gradient(90deg, #007AFF 0%, #5E5CE6 100%)'
    : 'linear-gradient(90deg, #AF52DE 0%, #FF2D55 100%)';

  return (
    <div className="progress-container">
      <div 
        className="progress-bar"
        style={{
          width: `${percent}%`,
          background: gradient
        }}
      >
        <div className="progress-shine"></div>
      </div>
    </div>
  );
}

export default App;