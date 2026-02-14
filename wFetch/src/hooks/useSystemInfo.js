import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export function useSystemInfo() {
  const [bits, setBits] = useState(null);
  const [waiting, setWaiting] = useState(true);
  const [mood, setMood] = useState(null);
  const memoryIntervalStarted = useRef(false);

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
        setBits((prev) => {
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
    if (waiting || !bits || memoryIntervalStarted.current) return;

    memoryIntervalStarted.current = true;

    const updateMemory = async () => {
      try {
        const memoryInfo = await invoke("get_memory_info");
        setBits((prevBits) => {
          if (!prevBits) return prevBits;
          return {
            ...prevBits,
            memory: memoryInfo,
          };
        });
      } catch {
        // Non-fatal; keep last known memory info.
      }
    };

    updateMemory();
    const interval = setInterval(updateMemory, 5000);

    return () => {
      clearInterval(interval);
      memoryIntervalStarted.current = false;
    };
  }, [waiting, bits]);

  return { bits, waiting, mood };
}
