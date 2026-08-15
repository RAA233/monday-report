import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Cells, ErrorState, Frame, PageHeader, Skeleton, Tag } from "../components/primitives";
import { importLicense, LICENSE_ACTIVATION_REQUEST_PATH, type LicenseImportResult, type LicenseStatus } from "../../lib/api";
import { bindingConfidenceLabel, formatLicenseDate, presentLicense, useLicense } from "../lib/license";

const SECTION_HEADING: CSSProperties = {
  fontSize: 19,
  letterSpacing: "0.03em",
  textTransform: "uppercase",
  margin: 0
};

/**
 * License — the in-SPA equivalent of the runtime wrapper's utilitarian /license
 * console, styled to match the app. Reads the machine's license status, offers the
 * (hashes-only) activation request as a download, and imports a signed license — all
 * through the wrapper's existing endpoints. When the wrapper is not present (a dev
 * SPA) or the status route errors, it says the status could not be read rather than
 * fabricating one, and offers a retry.
 */
export function License() {
  const { license, refresh } = useLicense();
  const fileRef = useRef<HTMLInputElement | null>(null);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<LicenseImportResult | null>(null);

  // Re-read on open: a license can have gone read-only since the shell mounted, so
  // the page (and the "Open the License page" path from a read-only refusal) must
  // show the current state, not a stale snapshot.
  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onImport() {
    if (importing) return; // in-flight re-entry guard (the button stays focusable)
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setResult({ imported: false, detail: "Choose a license file first." });
      return;
    }
    setImporting(true);
    setResult(null);
    try {
      const text = await file.text();
      const outcome = await importLicense(text);
      setResult(outcome);
      if (outcome.imported) {
        refresh();
        if (fileRef.current) fileRef.current.value = "";
      }
    } catch {
      setResult({
        imported: false,
        detail: "The license could not be imported — the license service is not reachable in this environment."
      });
    } finally {
      setImporting(false);
    }
  }

  const resultMessage = result
    ? result.imported
      ? "License imported. The updated status is shown above."
      : `The license was not imported. ${result.detail ?? "The file was rejected."}`
    : "";

  return (
    <section style={{ display: "grid", gap: 20, maxWidth: 760 }}>
      <PageHeader
        kicker="Trust"
        title="License"
        lede="This machine's Monday Report license: its status, how to request activation, and how to import a renewed license. Licensing is verified on this computer — nothing here is sent over the Internet."
      />

      {license.state === "loading" ? <Skeleton rows={2} label="Reading the license status" /> : null}

      {license.state === "error" ? (
        <ErrorState
          title="License status could not be read"
          message="The license status is not available right now. In the installed Monday Report Offline app this page shows the machine's license status and lets you import a renewed license; if you are running the installed app, try again."
          onRetry={refresh}
        />
      ) : null}

      {license.state === "ready" ? (
        <>
          <LicenseReady status={license.data} />

          <Frame as="section" aria-label="Activation request" style={{ padding: 16, display: "grid", gap: 8 }}>
            <h2 style={SECTION_HEADING}>Activation request</h2>
            <p className="text-muted" style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
              The activation request contains only hashed machine facts — no raw hardware identifiers — and
              it never leaves this computer unless you send it. Give it to your vendor to obtain a signed
              license, then import that license below.
            </p>
            <a className="btn btn-secondary" href={LICENSE_ACTIVATION_REQUEST_PATH} style={{ justifySelf: "start" }}>
              Download activation request
            </a>
          </Frame>

          <Frame as="section" aria-label="Import a license" style={{ padding: 16, display: "grid", gap: 8 }}>
            <h2 style={SECTION_HEADING}>Import a license</h2>
            <p className="text-muted" style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
              Select the signed license file your vendor issued. It is validated on this machine; a valid,
              newer license replaces the current one.
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input ref={fileRef} type="file" accept="application/json,.json,.lic" aria-label="License file" />
              <button
                type="button"
                className="btn btn-primary"
                onClick={onImport}
                // In-flight (not a standing condition): the button must stay focusable,
                // so aria-disabled + the onImport re-entry guard carry it, never native
                // `disabled` (which would blur the caret to <body>).
                aria-disabled={importing || undefined}
              >
                {importing ? "Importing…" : "Import license"}
              </button>
            </div>
            {/* Permanently mounted so the outcome is reliably announced (a region
                created together with its content often is not). */}
            <p
              role="status"
              aria-live="polite"
              style={{
                fontSize: 12.5,
                lineHeight: 1.55,
                margin: 0,
                minHeight: 0,
                color: result?.imported ? "var(--color-accent-800)" : "var(--color-neutral-800)"
              }}
            >
              {resultMessage}
            </p>
          </Frame>
        </>
      ) : null}
    </section>
  );
}

function LicenseReady({ status }: { status: LicenseStatus }) {
  const presentation = presentLicense(status);
  return (
    <Frame as="section" aria-label="License status" style={{ padding: 16 }}>
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ ...SECTION_HEADING, fontSize: 20, textTransform: "none", letterSpacing: 0 }}>
            {presentation.label}
          </h2>
          <Tag tone={presentation.tone}>{presentation.readOnly ? "Read-only" : "Operational"}</Tag>
        </div>
        <p style={{ fontSize: 13.5, lineHeight: 1.55, margin: 0 }}>{presentation.description}</p>
        <Cells
          label="License details"
          min={150}
          items={[
            { label: "Edition", value: status.edition && status.edition !== "none" ? status.edition : "—" },
            { label: "Expires", value: status.expires_at ? formatLicenseDate(status.expires_at) : "—" },
            ...(status.grace_until
              ? [{ label: "Grace until", value: formatLicenseDate(status.grace_until) }]
              : []),
            { label: "Support code", value: status.support_code },
            ...(status.machine_binding
              ? [
                  {
                    label: "Machine binding",
                    value: status.machine_binding.match === "match" ? "This machine" : "Mismatch",
                    detail: bindingConfidenceLabel(status.machine_binding.binding_confidence)
                  }
                ]
              : [])
          ]}
        />
      </div>
    </Frame>
  );
}
