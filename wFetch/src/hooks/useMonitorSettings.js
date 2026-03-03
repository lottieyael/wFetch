import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const STORAGE_KEY = "monitorIncidents";
const MAX_STORED = 50;

function loadStoredIncidents() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveIncidents(incidents) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(incidents.slice(0, MAX_STORED)));
  } catch {}
}

export function useMonitorSettings() {
  const [monitorEnabled, setMonitorEnabled] = useState(
    () => localStorage.getItem("monitorEnabled") === "true",
  );
  const [monitorSensitivity, setMonitorSensitivity] = useState(() =>
    parseInt(localStorage.getItem("monitorSensitivity") || "85", 10),
  );
  const [incidents, setIncidents] = useState(loadStoredIncidents);
  const [samples, setSamples] = useState([]);

  useEffect(() => {
    localStorage.setItem("monitorEnabled", monitorEnabled.toString());
    invoke("set_monitor_state", { enabled: monitorEnabled }).catch(() => {});
  }, [monitorEnabled]);

  useEffect(() => {
    localStorage.setItem("monitorSensitivity", monitorSensitivity.toString());
    invoke("set_monitor_sensitivity", { threshold: monitorSensitivity }).catch(() => {});
  }, [monitorSensitivity]);

  useEffect(() => {
    if (!monitorEnabled) {
      setSamples([]);
      return;
    }
    // Merge backend in-memory incidents with locally persisted ones
    invoke("get_monitor_incidents").then((backendIncidents) => {
      setIncidents((stored) => {
        const storedIds = new Set(stored.map((i) => i.id));
        const merged = [
          ...backendIncidents.filter((i) => !storedIds.has(i.id)),
          ...stored,
        ].slice(0, MAX_STORED);
        saveIncidents(merged);
        return merged;
      });
    }).catch(() => {});

    invoke("get_monitor_samples").then(setSamples).catch(() => {});

    const unlistenIncident = listen("monitor-incident", (event) => {
      setIncidents((prev) => {
        const updated = [event.payload, ...prev.filter((i) => i.id !== event.payload.id)]
          .slice(0, MAX_STORED);
        saveIncidents(updated);
        return updated;
      });
    });
    const unlistenSample = listen("monitor-sample", (event) => {
      setSamples((prev) => [...prev, event.payload].slice(-120));
    });

    return () => {
      unlistenIncident.then((unlisten) => unlisten());
      unlistenSample.then((unlisten) => unlisten());
    };
  }, [monitorEnabled]);

  const deleteIncident = useCallback((id) => {
    invoke("delete_monitor_incident", { id }).catch(() => {});
    setIncidents((prev) => {
      const updated = prev.filter((i) => i.id !== id);
      saveIncidents(updated);
      return updated;
    });
  }, []);

  const clearIncidents = useCallback(() => {
    invoke("clear_monitor_incidents").catch(() => {});
    setIncidents([]);
    saveIncidents([]);
  }, []);

  return {
    monitorEnabled,
    setMonitorEnabled,
    monitorSensitivity,
    setMonitorSensitivity,
    incidents,
    samples,
    deleteIncident,
    clearIncidents,
  };
}
