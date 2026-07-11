import { Download, ExternalLink, Filter, Search } from "lucide-react";
import type { Dispatch, JSX, SetStateAction } from "react";
import type { FailureEvent, FilterState } from "../data/domain";
import {
  filterFailures,
  formatHours,
  formatPercent,
  formatUsd,
  uniqueCompanies,
  uniqueTools
} from "../lib/analytics";
import { Badge } from "./Badge";

interface FailureExplorerProps {
  events: FailureEvent[];
  filters: FilterState;
  onFiltersChange: Dispatch<SetStateAction<FilterState>>;
}

export function FailureExplorer({
  events,
  filters,
  onFiltersChange
}: FailureExplorerProps): JSX.Element {
  const filteredEvents = filterFailures(events, filters);
  const companies = uniqueCompanies(events);
  const tools = uniqueTools(events);

  return (
    <main className="view-stack">
      <section className="workspace-title" aria-labelledby="explorer-title">
        <div>
          <p className="eyebrow">Investigation</p>
          <h1 id="explorer-title">Failure explorer</h1>
          <p>Filter every extracted event by source-backed field, confidence, and validation state.</p>
        </div>
        <button className="secondary-action" type="button">
          <Download size={18} aria-hidden="true" />
          Export CSV
        </button>
      </section>

      <section className="filter-panel" aria-label="Failure filters">
        <label className="search-box">
          <Search size={18} aria-hidden="true" />
          <input
            value={filters.query}
            onChange={(event) =>
              onFiltersChange((current) => ({ ...current, query: event.currentTarget.value }))
            }
            placeholder="Search event, well, company, tool, serial, formation"
          />
        </label>
        <FilterSelect
          label="Date"
          value={filters.dateRange}
          options={[
            ["all", "All dates"],
            ["30d", "Last 30 days"],
            ["90d", "Last 90 days"],
            ["6m", "Last 6 months"]
          ]}
          onChange={(value) =>
            onFiltersChange((current) => ({ ...current, dateRange: value as FilterState["dateRange"] }))
          }
        />
        <FilterSelect
          label="Company"
          value={filters.company}
          options={companies.map((company) => [company, company])}
          onChange={(value) => onFiltersChange((current) => ({ ...current, company: value }))}
        />
        <FilterSelect
          label="Tool"
          value={filters.toolType}
          options={tools.map((tool) => [tool, tool])}
          onChange={(value) => onFiltersChange((current) => ({ ...current, toolType: value }))}
        />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          options={[
            ["All severities", "All severities"],
            ["Critical", "Critical"],
            ["High", "High"],
            ["Medium", "Medium"],
            ["Low", "Low"]
          ]}
          onChange={(value) => onFiltersChange((current) => ({ ...current, severity: value }))}
        />
        <FilterSelect
          label="Validation"
          value={filters.validationStatus}
          options={[
            ["All validation", "All validation"],
            ["Validated", "Validated"],
            ["Needs review", "Needs review"],
            ["Conflict", "Conflict"],
            ["Rejected", "Rejected"]
          ]}
          onChange={(value) =>
            onFiltersChange((current) => ({ ...current, validationStatus: value }))
          }
        />
        <Filter size={18} aria-hidden="true" />
      </section>

      <section className="panel" aria-labelledby="failure-table-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Structured events</p>
            <h2 id="failure-table-title">{filteredEvents.length} matching failures</h2>
          </div>
          <Badge tone="info">citations attached</Badge>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Event</th>
                <th>Context</th>
                <th>Company/tool</th>
                <th>NPT</th>
                <th>Confidence</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((event) => (
                <tr key={event.id}>
                  <td>
                    <div className="event-cell">
                      <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
                      <strong>{event.eventType}</strong>
                      <span>{event.summary}</span>
                    </div>
                  </td>
                  <td>
                    <div className="stacked-cell">
                      <strong>{event.well}</strong>
                      <span>
                        {event.rig} / {event.section} / {event.depthMdFt.toLocaleString()} ft MD
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stacked-cell">
                      <strong>{event.company}</strong>
                      <span>
                        {event.toolType} / {event.toolSerial}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stacked-cell">
                      <strong>{formatHours(event.nptHours)}</strong>
                      <span>{formatUsd(event.costImpactUsd)}</span>
                    </div>
                  </td>
                  <td>
                    <div className="stacked-cell">
                      <strong>{formatPercent(event.confidence)}</strong>
                      <span>{validationLabel(event.validationStatus)}</span>
                    </div>
                  </td>
                  <td>
                    <button className="source-button" type="button">
                      <ExternalLink size={15} aria-hidden="true" />
                      {event.citations[0]?.file ?? "No source"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

interface FilterSelectProps {
  label: string;
  value: string;
  options: Array<[string, string]>;
  onChange: (value: string) => void;
}

function FilterSelect({ label, value, options, onChange }: FilterSelectProps): JSX.Element {
  return (
    <label className="filter-select">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.currentTarget.value)}>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </label>
  );
}

function severityTone(severity: FailureEvent["severity"]): "neutral" | "warning" | "danger" {
  if (severity === "Critical" || severity === "High") {
    return "danger";
  }
  if (severity === "Medium") {
    return "warning";
  }
  return "neutral";
}

function validationLabel(status: FailureEvent["validationStatus"]): string {
  const labels: Record<FailureEvent["validationStatus"], string> = {
    validated: "Validated",
    needs_review: "Needs review",
    conflict: "Conflict",
    rejected: "Rejected"
  };
  return labels[status];
}
