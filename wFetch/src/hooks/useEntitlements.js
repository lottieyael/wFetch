import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
export function useEntitlements() {
  const checkoutUrl = import.meta.env.VITE_LEMONSQUEEZY_CHECKOUT_URL || "";
  const devUnlockAllowed = import.meta.env.DEV;
  const isDevBuild = import.meta.env.TAURI_ENV_DEBUG === "true" || import.meta.env.DEV;
  const [entitlements, setEntitlements] = useState(null);
  const [entitlementsLoading, setEntitlementsLoading] = useState(true);
  const [devUnlocked, setDevUnlocked] = useState(() => {
    if (!devUnlockAllowed) return false;
    return localStorage.getItem("devUnlocked") === "true";
  });

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
  const isSubscribed = !!entitlements?.active;
  const effectiveSubscribed = devUnlocked || isSubscribed;
  return {
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
  };
}
