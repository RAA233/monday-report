import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Cells, ErrorState, Frame, PageHeader, Skeleton, Tag } from "../components/primitives";
import {
  removeOnlineConfig,
  saveOnlineConfig,
  testOnlineConnection,
  type ApiOnlineTestResult
} from "../../lib/api";
import { useWorkspace } from "../lib/workspace";

const SECTION_HEADING: CSSProperties = {
  fontSize: 19,
  letterSpacing: "0.03em",
  textTransform: "uppercase",
  margin: 0
};

const PROVIDER = "openai_compatible";

/**
 * Online AI — the optional page to configure a remote AI provider. It is OFF by default:
 * built-in analysis (and any local model) run entirely on this computer, and configuring
 * a provider here does not by itself send anything anywhere. Turning it on is a deliberate,
 * consented action, and it changes the privacy posture: your question and the selected
 * evidence are then sent to the configured provider over the Internet. The API key is
 * stored sealed on this computer and is never shown again.
 */
export function OnlineAI() {
  const { onlineConfig, reloadOnlineConfig, reloadProviderStatus } = useWorkspace();

  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [consented, setConsented] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [testResult, setTestResult] = useState<ApiOnlineTestResult | null>(null);
  const prefilled = useRef(false);

  useEffect(() => {
    reloadOnlineConfig();
  }, [reloadOnlineConfig]);

  // Prefill the non-secret fields once from the stored config (the key is never returned).
  useEffect(() => {
    if (prefilled.current) return;
    if (onlineConfig.state === "ready" && onlineConfig.data.configured) {
      setBaseUrl(onlineConfig.data.base_url ?? "");
      setModel(onlineConfig.data.model ?? "");
      prefilled.current = true;
    }
  }, [onlineConfig]);

  const currentInput = () => ({
    provider: PROVIDER,
    base_url: baseUrl.trim(),
    model: model.trim(),
    api_key: apiKey
  });

  async function onSave() {
    if (busy) return;
    if (!consented) {
      setSaveMessage("Confirm you understand that online AI sends your question and evidence to the provider.");
      return;
    }
    if (!baseUrl.trim() || !model.trim() || !apiKey) {
      setSaveMessage("Enter the endpoint, model, and API key. The stored key is not shown, so re-enter it to save.");
      return;
    }
    setBusy(true);
    setSaveMessage("");
    try {
      await saveOnlineConfig(currentInput());
      setApiKey("");
      setSaveMessage("Saved. The key is stored sealed on this computer and is not shown again.");
      reloadOnlineConfig();
      reloadProviderStatus();
    } catch {
      setSaveMessage("The configuration could not be saved on this system.");
    } finally {
      setBusy(false);
    }
  }

  async function onRemove() {
    if (busy) return;
    setBusy(true);
    setSaveMessage("");
    setTestResult(null);
    try {
      await removeOnlineConfig();
      setBaseUrl("");
      setModel("");
      setApiKey("");
      prefilled.current = true;
      setSaveMessage("Removed. Built-in analysis answers again.");
      reloadOnlineConfig();
      reloadProviderStatus();
    } catch {
      setSaveMessage("The configuration could not be removed.");
    } finally {
      setBusy(false);
    }
  }

  async function onTest() {
    if (busy) return;
    if (!baseUrl.trim() || !model.trim() || !apiKey) {
      setTestResult({ status: "misconfigured", detail: "Enter the endpoint, model, and API key to test." });
      return;
    }
    setBusy(true);
    setTestResult(null);
    try {
      const outcome = await testOnlineConnection(currentInput());
      setTestResult(outcome);
    } catch {
      setTestResult({ status: "unavailable", detail: "The connection test could not be run." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ display: "grid", gap: 20, maxWidth: 760 }}>
      <PageHeader
        kicker="Trust"
        title="Online AI"
        lede="Optional. Built-in analysis and any local model run entirely on this computer. Turning on an online provider sends your question and the selected evidence to that provider over the Internet — a deliberate choice you make here. Citations are always selected and verified on this computer."
      />

      {onlineConfig.state === "loading" ? <Skeleton rows={2} label="Reading the online AI configuration" /> : null}

      {onlineConfig.state === "unauthorized" ? (
        <p role="status" style={{ fontSize: 13, margin: 0 }}>
          Your role cannot view the online AI configuration. Ask an administrator to manage it.
        </p>
      ) : null}

      {onlineConfig.state === "error" ? (
        <ErrorState
          title="Online AI configuration could not be read"
          message="This is available in the installed Monday Report app. If you are running the installed app, try again."
          onRetry={reloadOnlineConfig}
        />
      ) : null}

      {onlineConfig.state === "ready" ? (
        <Frame as="section" aria-label="Online AI status" style={{ padding: 16, display: "grid", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
            <h2 style={{ ...SECTION_HEADING, fontSize: 20, textTransform: "none", letterSpacing: 0 }}>
              {onlineConfig.data.configured ? "Configured" : "Not configured"}
            </h2>
            <Tag tone={onlineConfig.data.configured ? "accent" : "neutral"}>
              {onlineConfig.data.configured ? "Provider set" : "Off"}
            </Tag>
          </div>
          <Cells
            label="Online AI details"
            min={150}
            items={[
              { label: "Endpoint", value: onlineConfig.data.base_url || "—" },
              { label: "Model", value: onlineConfig.data.model || "—" },
              { label: "API key", value: onlineConfig.data.has_key ? "Stored (not shown)" : "None" },
              {
                label: "Secure storage",
                value: onlineConfig.data.storage_available ? "Available" : "Unavailable",
                ok: onlineConfig.data.storage_available
              }
            ]}
          />
        </Frame>
      ) : null}

      <Frame as="section" aria-label="Configure online AI" style={{ padding: 16, display: "grid", gap: 12 }}>
        <h2 style={SECTION_HEADING}>Configure a provider</h2>
        <p className="text-muted" style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
          An OpenAI-compatible endpoint. Use the full API root (for example
          {" "}
          <code style={{ fontSize: 12 }}>https://api.example.com/v1</code>). Only a secure https address is
          accepted. The key is stored sealed on this computer and never shown again.
        </p>
        <label style={{ display: "grid", gap: 4, fontSize: 12.5 }}>
          Endpoint (https)
          <input
            className="input"
            type="url"
            inputMode="url"
            placeholder="https://api.example.com/v1"
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            aria-label="Online AI endpoint"
          />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 12.5 }}>
          Model
          <input
            className="input"
            type="text"
            placeholder="model name"
            value={model}
            onChange={(event) => setModel(event.target.value)}
            aria-label="Online AI model"
          />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 12.5 }}>
          API key {onlineConfig.state === "ready" && onlineConfig.data.has_key ? "(re-enter to change; the stored key is not shown)" : ""}
          <input
            className="input"
            type="password"
            autoComplete="off"
            placeholder="Enter API key"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            aria-label="Online AI API key"
          />
        </label>

        <Frame
          as="div"
          aria-label="Privacy notice"
          style={{ padding: 12, display: "grid", gap: 8, background: "var(--color-neutral-100)" }}
        >
          <strong style={{ fontSize: 12.5 }}>Before you enable online AI</strong>
          <p style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
            Online AI sends your question and the selected workspace evidence to the configured provider
            {baseUrl.trim() ? ` (${baseUrl.trim()})` : ""}
            {model.trim() ? ` · model ${model.trim()}` : ""} over the Internet. Citations are still selected and
            verified on this computer. Built-in analysis and any local model stay on this computer.
          </p>
          <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 12.5 }}>
            <input
              type="checkbox"
              checked={consented}
              onChange={(event) => setConsented(event.target.checked)}
              aria-label="Confirm online AI privacy notice"
            />
            I understand my question and selected evidence will be sent to this provider.
          </label>
        </Frame>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onSave}
            aria-disabled={busy || !consented || undefined}
          >
            {busy ? "Working…" : "Save securely"}
          </button>
          <button type="button" className="btn btn-secondary" onClick={onTest} aria-disabled={busy || undefined}>
            Test connection
          </button>
          <button type="button" className="btn btn-ghost" onClick={onRemove} aria-disabled={busy || undefined}>
            Remove key
          </button>
        </div>

        <p
          role="status"
          aria-live="polite"
          style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0, color: "var(--color-neutral-800)" }}
        >
          {testResult ? `Connection test: ${testResult.status} — ${testResult.detail}` : saveMessage}
        </p>

        <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.5, margin: 0 }}>
          To make online AI the active engine, set <code style={{ fontSize: 11.5 }}>MONDAY_REPORT_AI_PROVIDER=online</code>{" "}
          in the app environment and restart. Built-in analysis remains the default until you do.
        </p>
      </Frame>
    </section>
  );
}
