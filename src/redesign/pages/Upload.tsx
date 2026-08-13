import { useEffect, useMemo, useRef, useState } from "react";
import { directUploadFile, type ApiProcessingJob } from "../../lib/api";
import {
  Cells,
  EmptyState,
  ErrorState,
  Frame,
  GridCell,
  GridRow,
  GridTable,
  PageHeader,
  Skeleton,
  Tag,
  useRetryPresence
} from "../components/primitives";
import {
  apiUnreadReason,
  errorText,
  isBackendRefusal,
  useWorkspace
} from "../lib/workspace";

/**
 * Upload intake.
 *
 * Each selected file goes through the product's own `POST /uploads/direct`
 * (store, hash, audit, queue). Per-file outcomes keep the repository's
 * mutation-honesty rule: only a proven 4xx refusal is reported as "not stored";
 * any other failure says the outcome is UNKNOWN — the upload may have landed —
 * and offers a re-read of the processing queue rather than a definite claim.
 *
 * The queue and document lists are the provider's shared, permission-gated
 * reads. Jobs are drained by the out-of-process worker (`python -m
 * backend.app.worker`); this interface has no route to run it, and says so
 * instead of animating a pipeline it cannot observe.
 */
interface FileOutcome {
  name: string;
  bytes: number;
  status: "stored" | "refused" | "unknown";
  detail: string;
}

const JOB_TEMPLATE = "1.1fr 0.8fr 0.5fr 1fr";
const DOC_TEMPLATE = "1.4fr 1fr 0.6fr 0.7fr";

function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function inferSourceType(file: File, picked: "files" | "folder"): "zip" | "folder" | "files" {
  if (picked === "folder") return "folder";
  return file.name.toLowerCase().endsWith(".zip") ? "zip" : "files";
}

function relativePath(file: File): string {
  const withPath = file as File & { webkitRelativePath?: string };
  return withPath.webkitRelativePath || file.name;
}

export function Upload() {
  const {
    activeWorkspace,
    apiStatus,
    can,
    readOnly,
    processingJobs,
    reloadProcessingJobs,
    documents,
    reloadDocuments,
    showToast
  } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const [outcomes, setOutcomes] = useState<FileOutcome[]>([]);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    folderInputRef.current?.setAttribute("webkitdirectory", "");
    folderInputRef.current?.setAttribute("directory", "");
  }, []);

  const canUpload = can("manage_uploads");
  // Standing conditions only — permission, connectivity, workspace. The in-flight
  // state is aria-disabled plus an early return, never the native attribute.
  const uploadBlocked = readOnly || !canUpload || !workspaceId;

  async function handleFiles(list: FileList | null, picked: "files" | "folder") {
    const files = Array.from(list ?? []);
    if (files.length === 0 || uploadBlocked || !workspaceId) return;
    if (uploading) return;
    setUploading(true);
    const results: FileOutcome[] = [];
    for (const file of files) {
      const name = relativePath(file);
      try {
        const created = await directUploadFile({
          workspaceId,
          file,
          fileName: name,
          sourceType: inferSourceType(file, picked)
        });
        results.push({
          name,
          bytes: file.size,
          status: "stored",
          detail: `Stored, hashed (sha256 ${created.file.sha256.slice(0, 12)}…), audited, and queued for the worker. Malware check: ${created.file.malware_status}.`
        });
      } catch (caught) {
        // Only a 4xx proves the backend rejected the upload before applying it.
        // Anything else (5xx, gateway, network) leaves the effect unknown — the
        // file MAY be stored and queued — so the copy must not claim it is not.
        if (isBackendRefusal(caught)) {
          results.push({
            name,
            bytes: file.size,
            status: "refused",
            detail: `The backend refused this upload, so it was not stored. ${errorText(caught)}`
          });
        } else {
          results.push({
            name,
            bytes: file.size,
            status: "unknown",
            detail: `The request did not complete, so whether this file was stored is unknown — it may have landed. Re-read the processing queue below before uploading it again. ${errorText(caught)}`
          });
        }
      }
    }
    setOutcomes((current) => [...results, ...current]);
    setUploading(false);
    const stored = results.filter((item) => item.status === "stored").length;
    const unknown = results.filter((item) => item.status === "unknown").length;
    showToast(
      unknown > 0 ? "Outcome partly unknown" : stored === results.length ? "Stored" : "Some uploads refused",
      unknown > 0
        ? `${stored} of ${results.length} file(s) stored; ${unknown} did not complete and may have landed — re-read the queue before retrying.`
        : `${stored} of ${results.length} file(s) stored, hashed and queued for the worker.`
    );
    // One user intent (the upload) invalidates the queue snapshot it feeds.
    reloadProcessingJobs();
    reloadDocuments();
  }

  const jobCounts = useMemo(() => {
    if (processingJobs.state !== "ready") return null;
    const count = (status: ApiProcessingJob["status"]) =>
      processingJobs.data.filter((job) => job.status === status).length;
    return {
      total: processingJobs.data.length,
      queued: count("queued"),
      processing: count("processing"),
      complete: count("complete"),
      failed: count("failed")
    };
  }, [processingJobs]);

  const jobsRetry = useRetryPresence(processingJobs.state);
  const docsRetry = useRetryPresence(documents.state);

  return (
    <>
      <PageHeader
        kicker={`Intake · ${activeWorkspace?.name ?? "no workspace"}`}
        title="Upload rig reports"
        lede="Register PDFs, spreadsheets, text reports, emails, images and ZIPs into the audited intake path: each file is stored, hashed, malware-checked, audit-logged and queued. Parsing runs in the out-of-process worker, so a queued job stays queued until the worker drains it — nothing here simulates progress."
        actions={
          <>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                if (uploading) return;
                fileInputRef.current?.click();
              }}
              disabled={uploadBlocked}
              aria-disabled={uploading || undefined}
            >
              {uploading ? "Uploading…" : "Select files"}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                if (uploading) return;
                folderInputRef.current?.click();
              }}
              disabled={uploadBlocked}
              aria-disabled={uploading || undefined}
            >
              Select a folder
            </button>
          </>
        }
      />

      <input
        ref={fileInputRef}
        id="up-files"
        className="mr-visually-hidden"
        type="file"
        multiple
        aria-label="Select report files to upload"
        accept=".zip,.pdf,.xlsx,.xls,.docx,.doc,.csv,.txt,.eml,.msg,.png,.jpg,.jpeg,.tif,.tiff"
        onChange={(event) => {
          void handleFiles(event.currentTarget.files, "files");
          event.currentTarget.value = "";
        }}
      />
      <input
        ref={folderInputRef}
        id="up-folder"
        className="mr-visually-hidden"
        type="file"
        multiple
        aria-label="Select a report folder to upload"
        onChange={(event) => {
          void handleFiles(event.currentTarget.files, "folder");
          event.currentTarget.value = "";
        }}
      />

      {uploadBlocked ? (
        <p
          role="status"
          style={{ fontSize: 13, border: "1px solid var(--color-divider)", padding: "10px 14px", margin: 0 }}
        >
          {apiStatus === "checking" ? (
            <>Checking the workspace API — uploads are disabled until the session resolves.</>
          ) : apiStatus !== "connected" ? (
            <>{apiUnreadReason(apiStatus)}, so nothing can be uploaded.</>
          ) : !canUpload ? (
            <>
              This session lacks the <strong>manage_uploads</strong> permission, so nothing can be
              uploaded here. The backend refuses the intake route without it.
            </>
          ) : (
            <>No workspace is resolved, so there is no intake scope to upload into.</>
          )}
        </p>
      ) : null}

      {outcomes.length > 0 ? (
        <Frame as="section" aria-label="Upload outcomes" style={{ padding: 18, display: "grid", gap: 10 }}>
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            This session's uploads
          </h2>
          <div style={{ display: "grid", gap: 8 }}>
            {outcomes.map((outcome, index) => (
              <div
                key={`${outcome.name}-${index}`}
                style={{
                  display: "flex",
                  gap: 10,
                  alignItems: "baseline",
                  flexWrap: "wrap",
                  border: "1px solid var(--color-divider)",
                  padding: "8px 12px",
                  fontSize: 12.5
                }}
              >
                <Tag
                  tone={
                    outcome.status === "stored"
                      ? "accent"
                      : outcome.status === "refused"
                        ? "critical"
                        : "neutral"
                  }
                >
                  {outcome.status === "stored"
                    ? "stored"
                    : outcome.status === "refused"
                      ? "refused"
                      : "outcome unknown"}
                </Tag>
                <strong style={{ fontFamily: "var(--font-heading)" }}>{outcome.name}</strong>
                <span className="text-muted">{sizeLabel(outcome.bytes)}</span>
                <span style={{ flexBasis: "100%", lineHeight: 1.5 }}>{outcome.detail}</span>
              </div>
            ))}
          </div>
        </Frame>
      ) : null}

      <Frame as="section" aria-label="Processing queue" style={{ padding: 18, display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
            Processing queue
          </h2>
          <button
            type="button"
            className="btn btn-ghost"
            style={{ minHeight: 0, padding: "2px 6px", fontSize: 12 }}
            onClick={() => {
              if (jobsRetry.retrying) return;
              reloadProcessingJobs();
            }}
            disabled={apiStatus !== "connected" || !can("view_processing_status")}
            aria-disabled={jobsRetry.retrying || undefined}
          >
            Re-read the queue
          </button>
        </div>
        <p className="text-muted" style={{ fontSize: 12, margin: 0, maxWidth: "80ch" }}>
          Jobs are drained by the out-of-process worker, which this interface cannot run. A queued
          job here means the worker has not processed it yet — not that intake failed.
        </p>
        {processingJobs.state === "loading" ? <Skeleton rows={2} label="Loading the processing queue" /> : null}
        {processingJobs.state === "unauthorized" ? (
          <ErrorState
            title="Queue not visible to this session"
            message="This session lacks the view_processing_status permission, so the processing queue cannot be read here. This is not a statement that the queue is empty."
          />
        ) : null}
        {jobsRetry.show ? (
          <ErrorState
            title="Processing queue not read"
            message={
              jobsRetry.retrying
                ? "The queue is being read again."
                : `${processingJobs.state === "error" ? processingJobs.message : ""} This is not a statement that the queue is empty.`
            }
            onRetry={apiStatus === "connected" ? reloadProcessingJobs : undefined}
            retrying={jobsRetry.retrying}
          />
        ) : null}
        {jobCounts ? (
          <Cells
            label="Processing job counts"
            min={110}
            items={[
              { label: "Jobs", value: String(jobCounts.total) },
              { label: "Queued", value: String(jobCounts.queued) },
              { label: "Processing", value: String(jobCounts.processing) },
              { label: "Complete", value: String(jobCounts.complete) },
              {
                label: "Failed",
                value: String(jobCounts.failed),
                ok: jobCounts.failed === 0 ? true : false
              }
            ]}
          />
        ) : null}
        {processingJobs.state === "ready" && processingJobs.data.length === 0 ? (
          <EmptyState
            title="No processing jobs"
            body="The tenant queue was read and holds no jobs. Uploading a file queues one for the worker."
          />
        ) : null}
        {processingJobs.state === "ready" && processingJobs.data.length > 0 ? (
          <GridTable
            label="Processing jobs"
            columns={["Job", "Status", "Attempts", "Created"]}
            template={JOB_TEMPLATE}
            minWidth={520}
          >
            {[...processingJobs.data]
              .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
              .slice(0, 30)
              .map((job) => (
                <GridRow template={JOB_TEMPLATE} key={job.id}>
                  <GridCell>{job.job_type.replace(/_/g, " ")}</GridCell>
                  <GridCell>
                    <Tag
                      tone={
                        job.status === "failed"
                          ? "critical"
                          : job.status === "complete"
                            ? "accent"
                            : "outline"
                      }
                    >
                      {job.status}
                    </Tag>
                  </GridCell>
                  <GridCell>{job.attempts}</GridCell>
                  <GridCell>{new Date(job.created_at).toLocaleString()}</GridCell>
                </GridRow>
              ))}
          </GridTable>
        ) : null}
        {processingJobs.state === "ready" && processingJobs.data.length > 30 ? (
          <p className="text-muted" style={{ fontSize: 11.5, margin: 0 }}>
            Newest 30 of {processingJobs.data.length} job(s) shown.
          </p>
        ) : null}
      </Frame>

      <Frame as="section" aria-label="Parsed documents" style={{ padding: 18, display: "grid", gap: 12 }}>
        <h2 style={{ fontSize: 19, letterSpacing: "0.03em", textTransform: "uppercase", margin: 0 }}>
          Parsed documents
        </h2>
        {documents.state === "loading" ? <Skeleton rows={2} label="Loading parsed documents" /> : null}
        {documents.state === "unauthorized" ? (
          <ErrorState
            title="Documents not visible to this session"
            message="This session lacks the view_source_documents permission, so the parsed-document list cannot be read here. This is not a statement that no documents exist."
          />
        ) : null}
        {docsRetry.show ? (
          <ErrorState
            title="Documents not read"
            message={
              docsRetry.retrying
                ? "The list is being read again."
                : `${documents.state === "error" ? documents.message : ""} This is not a statement that no documents exist.`
            }
            onRetry={apiStatus === "connected" ? reloadDocuments : undefined}
            retrying={docsRetry.retrying}
          />
        ) : null}
        {documents.state === "ready" && documents.data.length === 0 ? (
          <EmptyState
            title="No parsed documents"
            body="The tenant document list was read and is empty. Documents appear here after the worker parses an uploaded file."
          />
        ) : null}
        {documents.state === "ready" && documents.data.length > 0 ? (
          <GridTable
            label="Parsed documents"
            columns={["Title", "Parser", "Chunks", "Status"]}
            template={DOC_TEMPLATE}
            minWidth={520}
          >
            {documents.data.slice(0, 30).map((doc) => (
              <GridRow template={DOC_TEMPLATE} key={doc.id}>
                <GridCell style={{ minWidth: 0, overflowWrap: "anywhere" }}>{doc.title}</GridCell>
                <GridCell>{doc.parser_name}</GridCell>
                <GridCell>{doc.chunk_count}</GridCell>
                <GridCell>
                  <Tag tone={doc.status === "complete" ? "accent" : doc.status === "failed" ? "critical" : "outline"}>
                    {doc.status}
                  </Tag>
                </GridCell>
              </GridRow>
            ))}
          </GridTable>
        ) : null}
      </Frame>
    </>
  );
}
