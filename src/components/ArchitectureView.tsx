import { BrainCircuit, DatabaseZap, GitBranch, KeyRound, Network, ServerCog } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { JSX } from "react";
import { pipelineStages, taxonomy } from "../data/domain";
import { Badge } from "./Badge";

export function ArchitectureView(): JSX.Element {
  return (
    <main className="view-stack">
      <section className="workspace-title" aria-labelledby="architecture-title">
        <div>
          <p className="eyebrow">Build map</p>
          <h1 id="architecture-title">Local AI-first architecture</h1>
          <p>Chat is the primary workflow. Dashboards, validation, and exports become supporting surfaces.</p>
        </div>
        <Badge tone="good">chat first</Badge>
      </section>

      <section className="architecture-grid" aria-label="Architecture modules">
        <ArchitectureCard
          icon={BrainCircuit}
          title="Local AI core"
          body="Tenant API routes classification, extraction, chat answers, and Monday Report drafting to a local model before approved hosted fallback."
          tags={["Ollama", "LM Studio", "private RAG"]}
        />
        <ArchitectureCard
          icon={ServerCog}
          title="API layer"
          body="Tenant-scoped endpoints for uploads, reports, failures, search, chat, validation, exports, and audit logs."
          tags={["FastAPI", "OpenAPI", "RBAC"]}
        />
        <ArchitectureCard
          icon={DatabaseZap}
          title="Data layer"
          body="PostgreSQL tables carry tenant IDs, confidence fields, source traceability, and row-level security policies."
          tags={["Postgres", "pgvector", "RLS"]}
        />
        <ArchitectureCard
          icon={GitBranch}
          title="Worker pipeline"
          body="Queued workers scan, parse, OCR, classify, extract, deduplicate, validate, index, and refresh dashboards."
          tags={["Celery", "Redis", "OCR"]}
        />
        <ArchitectureCard
          icon={Network}
          title="Retrieval"
          body="Hybrid retrieval combines structured filters, full-text search, embeddings, metadata, and citations."
          tags={["RAG", "FTS", "citations"]}
        />
        <ArchitectureCard
          icon={KeyRound}
          title="Security"
          body="Tenant isolation, signed object URLs, encryption, audit logging, malware scanning, and data residency controls."
          tags={["SOC 2", "CMK later", "audit"]}
        />
      </section>

      <section className="panel" aria-labelledby="pipeline-map-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Pipeline contract</p>
            <h2 id="pipeline-map-title">Processing services</h2>
          </div>
          <Badge tone="good">{pipelineStages.length} stages</Badge>
        </div>
        <div className="service-map">
          {pipelineStages.map((stage) => (
            <article key={stage.id}>
              <h3>{stage.label}</h3>
              <p>{stage.description}</p>
              <Badge tone={stage.deterministic ? "neutral" : "warning"}>
                {stage.deterministic ? "deterministic" : "AI + validation"}
              </Badge>
            </article>
          ))}
        </div>
      </section>

      <section className="panel" aria-labelledby="api-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">API surface</p>
            <h2 id="api-title">Production endpoints</h2>
          </div>
          <Badge tone="info">tenant scoped</Badge>
        </div>
        <div className="endpoint-grid">
          {[
            "/uploads",
            "/reports",
            "/failures",
            "/npt-events",
            "/tools",
            "/companies",
            "/search",
            "/chat/messages",
            "/validation-tasks",
            "/exports",
            "/predictions",
            "/admin/audit-logs"
          ].map((endpoint) => (
            <code key={endpoint}>{endpoint}</code>
          ))}
        </div>
      </section>
    </main>
  );
}

interface ArchitectureCardProps {
  icon: LucideIcon;
  title: string;
  body: string;
  tags: string[];
}

function ArchitectureCard({
  icon: Icon,
  title,
  body,
  tags
}: ArchitectureCardProps): JSX.Element {
  return (
    <article className="architecture-card">
      <div className="architecture-icon" aria-hidden="true">
        <Icon size={21} />
      </div>
      <h2>{title}</h2>
      <p>{body}</p>
      <div className="tag-row">
        {tags.map((tag) => (
          <span key={tag}>{tag}</span>
        ))}
      </div>
    </article>
  );
}
