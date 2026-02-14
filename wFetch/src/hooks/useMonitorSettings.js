import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export function useMonitorSettings() {
  const [monitorEnabled, setMonitorEnabled] = useState(
    () => localStorage.getItem("monitorEnabled") === "true",
  );
  const [monitorSensitivity, setMonitorSensitivity] = useState(() =>
    parseInt(localStorage.getItem("monitorSensitivity") || "85", 10),
  );
  const [incidents, setIncidents] = useState([]);

  useEffect(() => {
    localStorage.setItem("monitorEnabled", monitorEnabled.toString());
    invoke("set_monitor_state", { enabled: monitorEnabled }).catch(() => {});
  }, [monitorEnabled]);

  useEffect(() => {
    localStorage.setItem("monitorSensitivity", monitorSensitivity.toString());
    invoke("set_monitor_sensitivity", { threshold: monitorSensitivity }).catch(
      () => {},
    );
  }, [monitorSensitivity]);

  useEffect(() => {
    if (!monitorEnabled) return;

    invoke("get_monitor_incidents").then(setIncidents).catch(() => {});

    const unlistenPromise = listen("monitor-incident", (event) => {
      setIncidents((prev) => [event.payload, ...prev].slice(0, 10));
    });

    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, [monitorEnabled]);

  return {
    monitorEnabled,
    setMonitorEnabled,
    monitorSensitivity,
    setMonitorSensitivity,
    incidents,
  };
}
