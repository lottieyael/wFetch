import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { t } from "../translations";
import { InfoCard, InfoRow } from "../components/InfoComponents";

export function SettingsPage({
  currentPage,
  navigateTo,
  language,
  setLanguage,
  isDevBuild,

  checkoutUrl,
  devUnlockAllowed,
  devUnlocked,
  setDevUnlocked,

  entitlements,
  setEntitlements,
  entitlementsLoading,
  isSubscribed,
  effectiveSubscribed,

  theme,
  setTheme,
  saveTheme,
  setSaveTheme,

  systemHostname,

  monitorEnabled,
  setMonitorEnabled,
  monitorSensitivity,
  setMonitorSensitivity,
  incidents,
}) {
  const [licenseKey, setLicenseKey] = useState("");
  const [licenseBusy, setLicenseBusy] = useState(false);
  const [licenseOops, setLicenseOops] = useState(null);
  const [licenseOk, setLicenseOk] = useState(null);

  const [netDiagBusy, setNetDiagBusy] = useState(false);
  const [netDiagOops, setNetDiagOops] = useState(null);
  const [netDiagResult, setNetDiagResult] = useState(null);

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
        instance_name: systemHostname,
      });
      setEntitlements(result);
      setLicenseKey("");
      setLicenseOk(t("settings.subscription.activated", language));
    } catch (err) {
      const msg =
        typeof err === "string"
          ? err
          : err?.message ||
            err?.toString() ||
            t("settings.subscription.activationFailed", language);
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
          : err?.message ||
            err?.toString() ||
            t("settings.subscription.refreshFailed", language);
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
          : err?.message ||
            err?.toString() ||
            t("settings.subscription.deactivationFailed", language);
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
    <>
      <header className="header">
        <button type="button" className="back-button" onClick={() => navigateTo("overview")}>
          {t("settings.backButton", language)}
        </button>

        <div className="header-content">
          <h1 className="app-title">{pageTitle}</h1>
          {/*<p className="app-subtitle">{t("settings.subtitle", language)}</p>*/}
        </div>

        <div style={{ width: "110px" }}></div>
      </header>

      <div
        className={`info-grid settings-grid ${currentPage !== "settings" ? "single-card-page" : ""}`}
      >
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

              {entitlements?.customer_email && (
                <div className="status-meta">{entitlements.customer_email}</div>
              )}
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
                  <button type="button" className="pill-toggle" disabled={licenseBusy} onClick={refreshLicense}>
                    {t("settings.subscription.refresh", language)}
                  </button>
                  <button type="button" className="pill-toggle" disabled={licenseBusy} onClick={deactivateLicense}>
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
                <div className="setting-label" style={{ marginBottom: "10px" }}>
                  {t("settings.monitor.viewIncidents", language)}
                </div>
                {incidents.map((inc) => (
                  <div key={inc.id} className="incident-item">
                    <div className="incident-header">
                      <span>{new Date(inc.timestamp * 1000).toLocaleTimeString()}</span>
                      <span className="incident-cpu">{inc.total_cpu.toFixed(1)}% CPU</span>
                    </div>
                    <div className="incident-processes">
                      {inc.processes.slice(0, 3).map((p) => (
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
    </>
  );
}
