import { useEffect, useMemo, useRef, useState } from "react";
import type { JSX } from "react";
import {
  Archive,
  FileArchive,
  FileSpreadsheet,
  FileText,
  FolderUp,
  Image,
  Mail,
  UploadCloud
} from "lucide-react";
import type { UploadInventoryItem } from "../data/domain";
import { directUploadFile } from "../lib/api";
import { buildInventory } from "../lib/analytics";
import { Badge } from "./Badge";
import { PipelineBoard } from "./PipelineBoard";

interface UploadPanelProps {
  inventory: UploadInventoryItem[];
  onInventoryChange: (inventory: UploadInventoryItem[]) => void;
  workspaceId?: string;
}

export function UploadPanel({
  inventory,
  onInventoryChange,
  workspaceId
}: UploadPanelProps): JSX.Element {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const [uploadStatus, setUploadStatus] = useState<"idle" | "syncing" | "synced" | "fallback" | "failed">("idle");
  const [uploadMessage, setUploadMessage] = useState("Select reports to create an audited backend intake record.");

  useEffect(() => {
    folderInputRef.current?.setAttribute("webkitdirectory", "");
    folderInputRef.current?.setAttribute("directory", "");
  }, []);

  const counts = useMemo(
    () => ({
      files: inventory.length,
      duplicates: inventory.filter((item) => item.status === "duplicate").length,
      ocr: inventory.filter((item) => item.status === "needs_ocr").length,
      unsupported: inventory.filter((item) => item.status === "unsupported").length
    }),
    [inventory]
  );

  function handleFiles(files: FileList | null, sourceType: "zip" | "folder" | "files"): void {
    const selectedFiles = Array.from(files ?? []);
    const nextInventory = buildInventory(selectedFiles);
    onInventoryChange(nextInventory);

    if (selectedFiles.length === 0) {
      setUploadStatus("idle");
      setUploadMessage("Select reports to create an audited backend intake record.");
      return;
    }

    if (!workspaceId) {
      setUploadStatus("fallback");
      setUploadMessage("Inventory is local-only until the API workspace context is available.");
      return;
    }

    void syncUploads(selectedFiles, sourceType);
  }

  async function syncUploads(files: File[], sourceType: "zip" | "folder" | "files"): Promise<void> {
    setUploadStatus("syncing");
    setUploadMessage(`Storing and auditing ${files.length} file(s).`);

    try {
      let completed = 0;
      for (const file of files) {
        const relativePath = getRelativePath(file);
        await directUploadFile({
          workspaceId: workspaceId as string,
          file,
          fileName: relativePath,
          sourceType: inferSourceType(file, sourceType)
        });
        completed += 1;
      }
      setUploadStatus("synced");
      setUploadMessage(`Stored, hashed, and audited ${completed} file(s).`);
    } catch {
      setUploadStatus("failed");
      setUploadMessage("Local inventory is visible, but backend upload audit failed. Check API status.");
    }
  }

  return (
    <main className="view-stack">
      <section className="upload-hero" aria-labelledby="upload-title">
        <div>
          <p className="eyebrow">Intake</p>
          <h1 id="upload-title">Upload rig reports</h1>
          <p>
            Register ZIPs, folders, PDFs, Excel sheets, Word files, emails, images, and mixed
            report packages into one audited processing batch.
          </p>
        </div>
        <div className="upload-status-panel">
          <Badge tone={uploadStatusTone(uploadStatus)}>{uploadStatus}</Badge>
          <span>{uploadMessage}</span>
        </div>
        <div className="upload-actions">
          <button className="primary-action" type="button" onClick={() => fileInputRef.current?.click()}>
            <UploadCloud size={18} aria-hidden="true" />
            ZIP or files
          </button>
          <button className="secondary-action" type="button" onClick={() => folderInputRef.current?.click()}>
            <FolderUp size={18} aria-hidden="true" />
            Folder upload
          </button>
          <input
            ref={fileInputRef}
            className="hidden-input"
            type="file"
            multiple
            accept=".zip,.pdf,.xlsx,.xls,.docx,.doc,.csv,.txt,.eml,.msg,.png,.jpg,.jpeg,.tif,.tiff"
            onChange={(event) => handleFiles(event.currentTarget.files, "files")}
          />
          <input
            ref={folderInputRef}
            className="hidden-input"
            type="file"
            multiple
            onChange={(event) => handleFiles(event.currentTarget.files, "folder")}
          />
        </div>
      </section>

      <div className="upload-stat-grid">
        <UploadStat label="Files inventoried" value={counts.files} />
        <UploadStat label="Duplicate candidates" value={counts.duplicates} />
        <UploadStat label="OCR routed" value={counts.ocr} />
        <UploadStat label="Parser gaps" value={counts.unsupported} />
      </div>

      <PipelineBoard inventory={inventory} />

      <section className="panel" aria-labelledby="inventory-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Batch manifest</p>
            <h2 id="inventory-title">File inventory</h2>
          </div>
          <Badge tone={inventory.length > 0 ? "good" : "neutral"}>
            {inventory.length > 0 ? "ready for workers" : "waiting for files"}
          </Badge>
        </div>
        {inventory.length === 0 ? (
          <div className="empty-state">
            <Archive size={28} aria-hidden="true" />
            <p>Select files or a folder to simulate the intake manifest.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Family</th>
                  <th>Size</th>
                  <th>Status</th>
                  <th>Handling</th>
                </tr>
              </thead>
              <tbody>
                {inventory.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <div className="file-cell">
                        <FileFamilyIcon family={item.reportFamily} />
                        <span>{item.relativePath}</span>
                      </div>
                    </td>
                    <td>{item.reportFamily}</td>
                    <td>{formatBytes(item.size)}</td>
                    <td>
                      <Badge tone={statusTone(item.status)}>{item.status.replace("_", " ")}</Badge>
                    </td>
                    <td>{item.warning ?? "Deterministic parser candidate."}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}

function getRelativePath(file: File): string {
  const fileWithRelativePath = file as File & { webkitRelativePath?: string };
  return fileWithRelativePath.webkitRelativePath || file.name;
}

function inferSourceType(file: File, selectedSourceType: "zip" | "folder" | "files"): "zip" | "folder" | "files" {
  if (selectedSourceType === "folder") {
    return "folder";
  }
  return file.name.toLowerCase().endsWith(".zip") ? "zip" : "files";
}

function uploadStatusTone(status: "idle" | "syncing" | "synced" | "fallback" | "failed"): "neutral" | "good" | "warning" | "danger" | "info" {
  if (status === "synced") {
    return "good";
  }
  if (status === "syncing") {
    return "info";
  }
  if (status === "failed") {
    return "danger";
  }
  if (status === "fallback") {
    return "warning";
  }
  return "neutral";
}

interface UploadStatProps {
  label: string;
  value: number;
}

function UploadStat({ label, value }: UploadStatProps): JSX.Element {
  return (
    <section className="upload-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

interface FileFamilyIconProps {
  family: UploadInventoryItem["reportFamily"];
}

function FileFamilyIcon({ family }: FileFamilyIconProps): JSX.Element {
  const Icon =
    family === "Archive"
      ? FileArchive
      : family === "Email"
        ? Mail
        : family === "Image/OCR"
          ? Image
          : family.includes("report") || family === "Lessons learned"
            ? FileText
            : FileSpreadsheet;
  return <Icon size={17} aria-hidden="true" />;
}

function statusTone(status: UploadInventoryItem["status"]): "neutral" | "good" | "warning" | "danger" {
  if (status === "parsed") {
    return "good";
  }
  if (status === "needs_ocr" || status === "duplicate") {
    return "warning";
  }
  if (status === "unsupported") {
    return "danger";
  }
  return "neutral";
}

function formatBytes(bytes: number): string {
  if (bytes === 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}
