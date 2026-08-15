import { useRef, useState } from "react";
import { Cells, ErrorState, Frame, PageHeader, Skeleton, Tag } from "../components/primitives";
import { importLicense, LICENSE_ACTIVATION_REQUEST_PATH, type LicenseImportResult, type LicenseStatus } from "../../lib/api";
import { formatLicenseDate, presentLicense, useLicense } from "../lib/license";

/**
 * License — the in-SPA equivalent of the runtime wrapper's utilitarian /license
 * console, styled to match the app. Reads the machine's license status, offers the
 * (hashes-only) activation request as a download, and imports a signed license — all
 * through the wrapper's existing endpoints. When the wrapper is not present (a dev
 * SPA), it says the license service is unavailable rather than fabricating a status.
 */
export function License() {
  const { license, refresh } = useLicense();
  const fileRef = useRef<HTMLInputElement | null>(null);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<LicenseImportResult | null>(null);

  async function onImport() {
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
        detail: "The license could not be imported here — the license service is not reachable in this environment."
      });
    } finally {
      setImporting(false);
    }
  }

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
          title="License status is not available here"
          message="This environment is not served by the offline runtime, so the license service cannot be reached. In the installed Monday Report Offline app this page shows the machine's license status and lets you import a renewed license."
        />
      ) : null}

      {license.state === "ready" ? (
        <>
          <LicenseReady status={license.data} />

          <Frame style={{ padding: 16 }}>
            <div style={{ display: "grid", gap: 8 }}>
              <strong
                style={{
                  fontFamily: "var(--font-heading)",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  fontSize: 13
                }}
              >
                Activation request
              </strong>
              <p className="text-muted" style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
                The activation request contains only hashed machine facts — no raw hardware identifiers — and
                it never leaves this computer unless you send it. Give it to your vendor to obtain a signed
                license, then import that license below.
              </p>
              <a className="btn btn-secondary" href={LICENSE_ACTIVATION_REQUEST_PATH} style={{ justifySelf: "start" }}>
                Download activation request
              </a>
            </div>
          </Frame>

          <Frame style={{ padding: 16 }}>
            <div style={{ display: "grid", gap: 8 }}>
              <strong
                style={{
                  fontFamily: "var(--font-heading)",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  fontSize: 13
                }}
              >
                Import a license
              </strong>
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
                  disabled={importing}
                  aria-disabled={importing || undefined}
                >
                  {importing ? "Importing…" : "Import license"}
                </button>
              </div>
              {result ? (
                <p
                  role="status"
                  style={{
                    fontSize: 12.5,
                    lineHeight: 1.55,
                    margin: 0,
                    color: result.imported ? "var(--color-accent-800)" : "var(--color-neutral-800)"
                  }}
                >
                  {result.imported
                    ? `License imported — the status is now “${result.state}”${
                        result.expires_at ? `, valid through ${formatLicenseDate(result.expires_at)}` : ""
                      }.`
                    : `The license was not imported.${result.reason_code ? ` (${result.reason_code})` : ""}${
                        result.detail ? ` ${result.detail}` : ""
                      }`}
                </p>
              ) : null}
            </div>
          </Frame>
        </>
      ) : null}
    </section>
  );
}

function LicenseReady({ status }: { status: LicenseStatus }) {
  const presentation = presentLicense(status);
  return (
    <Frame style={{ padding: 16 }}>
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
          <strong style={{ fontFamily: "var(--font-heading)", fontSize: 18 }}>{presentation.label}</strong>
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
                    detail: status.machine_binding.binding_confidence
                  }
                ]
              : [])
          ]}
        />
      </div>
    </Frame>
  );
}
