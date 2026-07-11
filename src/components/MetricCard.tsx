import type { LucideIcon } from "lucide-react";
import type { JSX } from "react";

interface MetricCardProps {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone?: "blue" | "green" | "amber" | "red";
}

export function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = "blue"
}: MetricCardProps): JSX.Element {
  return (
    <section className={`metric-card metric-${tone}`} aria-label={label}>
      <div className="metric-icon" aria-hidden="true">
        <Icon size={20} strokeWidth={2} />
      </div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{detail}</span>
      </div>
    </section>
  );
}
