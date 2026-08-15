import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { getLicenseStatus, type LicenseStatus } from "../../lib/api";
import type { Loadable } from "./workspace";

/**
 * The machine's offline license, read from the runtime wrapper that serves this SPA.
 *
 * `license.state` is honest about observability:
 *   - `ready`  => the wrapper answered; `data` is its own reported decision.
 *   - `error`  => the license service is not reachable from here (a dev SPA not
 *                 served by the wrapper). The UI then says so; it never invents a
 *                 state, and it never infers "read-only" from a successful data read
 *                 (reads are not license-gated).
 *
 * The wrapper is the single authority: mutations are refused with 423 only when it
 * reports a non-operational state, and this surface reflects that state — it does not
 * re-derive it.
 */
interface LicenseContextValue {
  license: Loadable<LicenseStatus>;
  refresh: () => void;
}

const LicenseContext = createContext<LicenseContextValue | null>(null);

export function LicenseProvider({ children }: { children: ReactNode }) {
  const [license, setLicense] = useState<Loadable<LicenseStatus>>({ state: "loading" });
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLicense({ state: "loading" });
    getLicenseStatus()
      .then((status) => {
        if (!cancelled) setLicense({ state: "ready", data: status });
      })
      .catch(() => {
        if (!cancelled) {
          setLicense({ state: "error", message: "The license service is not reachable from here." });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [tick]);

  return <LicenseContext.Provider value={{ license, refresh }}>{children}</LicenseContext.Provider>;
}

export function useLicense(): LicenseContextValue {
  const value = useContext(LicenseContext);
  if (!value) throw new Error("useLicense must be used within a LicenseProvider");
  return value;
}

export interface LicensePresentation {
  label: string;
  tone: "accent" | "neutral" | "critical";
  /** The runtime is read-only: new questions, reports and uploads are paused. Mirrors
   *  the wrapper's own `read_only` flag / non-operational decision. */
  readOnly: boolean;
  /** A soft advisory (expiring soon / grace) that is still fully operational. */
  advisory: boolean;
  description: string;
}

/** ISO-8601 → a short readable date; falls back to the raw string if unparseable. */
export function formatLicenseDate(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/**
 * Customer-facing wording for each license state the wrapper can report. The single
 * source of truth for both the app-wide banner and the License page, so they never
 * disagree. Unknown/rare states fall through to a safe "not valid → read-only".
 */
export function presentLicense(status: LicenseStatus): LicensePresentation {
  const when = (iso: string | null) => (iso ? formatLicenseDate(iso) : null);
  switch (status.state) {
    case "valid":
      return {
        label: "Active",
        tone: "accent",
        readOnly: false,
        advisory: false,
        description: status.expires_at
          ? `This machine's license is active, valid through ${when(status.expires_at)}.`
          : "This machine's license is active."
      };
    case "expiring_soon":
      return {
        label: "Active — expiring soon",
        tone: "neutral",
        readOnly: false,
        advisory: true,
        description: `This machine's license is active but expires ${when(status.expires_at) ?? "soon"}. Renew it to avoid an interruption.`
      };
    case "grace":
      return {
        label: "In grace period",
        tone: "neutral",
        readOnly: false,
        advisory: true,
        description: `The license has expired but is in its grace period${
          status.grace_until ? ` until ${when(status.grace_until)}` : ""
        }. Renew it now — after the grace period the app becomes read-only.`
      };
    case "expired_read_only":
      return {
        label: "Read-only — license expired",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description:
          "The license has expired past its grace period, so new questions, reports and uploads are paused. Existing data, answers and backups stay available. Import a renewed license to resume."
      };
    case "no_license":
      return {
        label: "No license installed",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description:
          "No license is installed on this machine, so the app is read-only. Download the activation request below, obtain a signed license, and import it."
      };
    case "machine_mismatch":
      return {
        label: "License is for a different machine",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description:
          "This license was issued for a different installation or machine, so the app is read-only. Request a license for this machine using the activation request below."
      };
    case "not_yet_valid":
      return {
        label: "Not yet valid",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description: `This license is not valid yet${
          status.not_before ? ` (valid from ${when(status.not_before)})` : ""
        }, or this machine's clock is behind. The app is read-only until it becomes valid.`
      };
    case "clock_rollback_detected":
      return {
        label: "Clock rollback detected",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description:
          "This machine's clock appears to have moved backwards relative to the last trusted time, so the license cannot be trusted and the app is read-only. Correct the system clock."
      };
    case "provider_unavailable":
      return {
        label: "Licensing unavailable",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description: "The licensing component is not available in this build, so the app is read-only."
      };
    default:
      // invalid_signature / corrupt_license / unsupported_license_version /
      // product_version_not_permitted / state_tampered and any future state.
      return {
        label: "License not valid",
        tone: "critical",
        readOnly: true,
        advisory: false,
        description:
          "The installed license could not be validated, so the app is read-only. Import a valid signed license, or contact support with the code shown on the License page."
      };
  }
}

/**
 * App-wide license banner. Shown on every in-shell page ONLY when the wrapper reports
 * a read-only state or a soft advisory (expiring/grace). It is not shown on a
 * successful data read alone, while loading, or when the license service is
 * unreachable — it reflects only the wrapper's own reported state.
 */
export function LicenseBanner() {
  const { license } = useLicense();
  if (license.state !== "ready") return null;
  const presentation = presentLicense(license.data);
  if (!presentation.readOnly && !presentation.advisory) return null;
  const critical = presentation.readOnly;
  return (
    <div
      role={critical ? "alert" : "status"}
      style={{
        display: "flex",
        gap: 10,
        alignItems: "baseline",
        flexWrap: "wrap",
        padding: "9px clamp(14px,3vw,28px)",
        borderBlockEnd: "1px solid var(--color-divider)",
        background: critical ? "color-mix(in srgb, var(--color-accent) 12%, var(--color-bg))" : "var(--color-surface)",
        fontSize: 13
      }}
    >
      <strong
        style={{
          fontFamily: "var(--font-heading)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          fontSize: 12.5
        }}
      >
        {critical ? "Read-only" : "License notice"}
      </strong>
      <span style={{ flex: "1 1 320px", minWidth: 0 }}>{presentation.description}</span>
      <Link className="btn btn-ghost" to="/app/license" style={{ minHeight: 0, padding: "0 4px", fontSize: 13 }}>
        Open License
      </Link>
    </div>
  );
}
