import { CheckCircle2, CircleDashed, LockKeyhole, SearchCheck } from "lucide-react";
import type { JSX } from "react";
import type { PipelineStage, UploadInventoryItem } from "../data/domain";
import { pipelineStages } from "../data/domain";
import { Badge } from "./Badge";

interface PipelineBoardProps {
  inventory: UploadInventoryItem[];
}

export function PipelineBoard({ inventory }: PipelineBoardProps): JSX.Element {
  const progress = getProgress(inventory);

  return (
    <section className="panel pipeline-panel" aria-labelledby="pipeline-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Processing</p>
          <h2 id="pipeline-title">Document intelligence pipeline</h2>
        </div>
        <Badge tone={progress === 100 ? "good" : "info"}>{progress}% staged</Badge>
      </div>
      <div className="pipeline-track">
        {pipelineStages.map((stage, index) => (
          <PipelineStageCard
            key={stage.id}
            stage={stage}
            active={progress >= (index + 1) * 16}
            complete={progress >= (index + 1) * 16 + 8}
          />
        ))}
      </div>
    </section>
  );
}

interface PipelineStageCardProps {
  stage: PipelineStage;
  active: boolean;
  complete: boolean;
}

function PipelineStageCard({ stage, active, complete }: PipelineStageCardProps): JSX.Element {
  const Icon = complete ? CheckCircle2 : active ? SearchCheck : CircleDashed;

  return (
    <article className={`pipeline-stage ${active ? "is-active" : ""}`}>
      <div className="stage-icon" aria-hidden="true">
        <Icon size={18} />
      </div>
      <div>
        <div className="stage-title">
          <h3>{stage.label}</h3>
          {stage.deterministic ? (
            <Badge tone="neutral">deterministic</Badge>
          ) : (
            <Badge tone="warning">AI review</Badge>
          )}
        </div>
        <p>{stage.description}</p>
      </div>
    </article>
  );
}

function getProgress(inventory: UploadInventoryItem[]): number {
  if (inventory.length === 0) {
    return 18;
  }

  const parsed = inventory.filter(
    (item) => item.status === "parsed" || item.status === "needs_ocr" || item.status === "duplicate"
  ).length;
  const ratio = parsed / Math.max(inventory.length, 1);
  const progress = 38 + Math.round(ratio * 62);
  return Math.min(progress, 100);
}

export function SecurityStrip(): JSX.Element {
  return (
    <section className="security-strip" aria-label="Security posture">
      <LockKeyhole size={18} aria-hidden="true" />
      <span>Local AI first</span>
      <span>Tenant isolation</span>
      <span>RLS-ready schema</span>
      <span>Source citations</span>
      <span>Audit trail</span>
      <span>No training by default</span>
    </section>
  );
}
