import type { JSX, ReactNode } from "react";

interface BadgeProps {
  children: ReactNode;
  tone?: "neutral" | "good" | "warning" | "danger" | "info";
}

export function Badge({ children, tone = "neutral" }: BadgeProps): JSX.Element {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
