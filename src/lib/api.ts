const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const API_KEY = import.meta.env.VITE_MONDAY_REPORT_API_KEY as string | undefined;

export interface ApiTenant {
  id: string;
  name: string;
  slug: string;
  local_llm_policy: {
    mode: string;
    hosted_fallback_enabled: boolean;
    allowed_local_runtimes?: string[];
  };
}

export interface ApiUser {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string;
  roles: string[];
}

export interface ApiSession {
  tenant: ApiTenant;
  user: ApiUser;
}

export interface ApiWorkspace {
  id: string;
  tenant_id: string;
  name: string;
  asset?: string | null;
  campaign?: string | null;
  status: string;
}

export interface ApiCitation {
  id: string;
  file_id?: string | null;
  locator_type: string;
  locator: Record<string, unknown>;
  snippet: string;
  confidence: number;
}

export interface ApiChatResponse {
  answer: string;
  citations: ApiCitation[];
  followups: string[];
  confidence_notes: string[];
  export_actions: string[];
  workflow_steps: {
    step: string;
    status: "ready" | "active" | "blocked" | "complete" | "watch";
    detail: string;
    command?: string | null;
  }[];
  insight_cards: {
    label: string;
    value: string;
    detail: string;
    tone: "good" | "warning" | "danger" | "info";
  }[];
  risk_register: {
    title: string;
    severity: "low" | "medium" | "high" | "critical";
    detail: string;
    mitigation: string;
  }[];
  tool_actions: {
    label: string;
    prompt: string;
    detail: string;
    kind: "plan" | "draft" | "schematic" | "audit" | "export" | "source";
  }[];
}

export interface ApiReportDraft {
  workspace_id: string;
  generated_at: string;
  report_date: string;
  report_no: string;
  well: string;
  rig: string;
  operator: string;
  phase: string;
  hole_size: string;
  md_ft: string;
  tvd_ft: string;
  mud_weight: string;
  present_ops: string;
  next_ops: string;
  safety: string;
  risks: string;
  casing_program: string;
  operations_log: string;
  evidence_summary: string[];
  source_document_count: number;
  source_chunk_count: number;
  failure_count: number;
  open_validation_tasks: number;
  citation_count: number;
  validation_gate: "clear" | "review_required";
  citations: ApiCitation[];
  confidence_notes: string[];
}

export interface ApiUpload {
  id: string;
  tenant_id: string;
  workspace_id: string;
  submitted_by: string;
  source_type: "zip" | "folder" | "files";
  status: string;
  created_at: string;
}

export interface ApiUploadFileRecord {
  id: string;
  tenant_id: string;
  upload_id: string;
  original_path: string;
  storage_uri: string;
  sha256: string;
  mime_type: string;
  byte_size: number;
  status: string;
  malware_status: string;
}

export interface ApiUploadCreateResponse {
  upload: ApiUpload;
  file: ApiUploadFileRecord;
  signed_url: string;
}

export interface ApiAuditLog {
  id: string;
  tenant_id: string;
  actor_user_id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  previous_hash?: string | null;
  entry_hash?: string | null;
}

export interface ApiAuditIntegrityStatus {
  status: "empty" | "sealed" | "legacy" | "broken";
  total_events: number;
  hashed_events: number;
  legacy_events: number;
  broken_events: number;
  latest_hash?: string | null;
  detail: string;
}

export interface ApiProcessingJob {
  id: string;
  tenant_id: string;
  upload_id: string;
  file_id?: string | null;
  job_type: string;
  status: "queued" | "processing" | "complete" | "failed";
  attempts: number;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ApiParsedDocument {
  id: string;
  tenant_id: string;
  workspace_id: string;
  upload_id: string;
  file_id: string;
  title: string;
  parser_name: string;
  status: "queued" | "processing" | "complete" | "failed";
  text_preview: string;
  chunk_count: number;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ApiFailureRecord {
  id: string;
  tenant_id: string;
  workspace_id: string;
  event_type: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  summary: string;
  company: string;
  tool_type: string;
  tool_serial: string;
  npt_hours: number;
  confidence: number;
  validation_status: "open" | "validated" | "rejected" | "conflict";
  citations: ApiCitation[];
}

export interface ApiValidationTask {
  id: string;
  tenant_id: string;
  target_type: "failure" | "npt_event" | "company" | "tool" | "citation" | "file";
  target_id: string;
  reason: string;
  priority: "low" | "medium" | "high" | "critical";
  status: "open" | "validated" | "rejected" | "conflict";
  resolution_note?: string | null;
  created_at: string;
}

export interface ApiMondayReport {
  id: string;
  tenant_id: string;
  workspace_id: string;
  period_start: string;
  period_end: string;
  status: "draft" | "review" | "approved" | "exported";
  report_json: Record<string, unknown>;
  created_at: string;
}

export interface ApiReportExport {
  id: string;
  tenant_id: string;
  report_id: string;
  format: "json" | "csv" | "html" | "pdf" | "xlsx";
  storage_uri: string;
  sha256: string;
  byte_size: number;
  created_at: string;
}

interface ExportMondayReportOptions {
  allowUnresolvedValidation?: boolean;
}

export interface ApiClientDataReadinessCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  remediation: string;
}

export interface ApiClientDataReadiness {
  mode: "demo" | "client";
  status: "ready" | "not_ready";
  ready: boolean;
  generated_at: string;
  checks: ApiClientDataReadinessCheck[];
}

export interface ApiLocalAiStatus {
  runtime: "ollama" | "lm_studio" | "unconfigured";
  configured: boolean;
  reachable: boolean;
  model_available: boolean;
  endpoint?: string | null;
  model?: string | null;
  hosted_fallback_enabled: boolean;
  detail: string;
}

export interface ApiRuntimeBackendStatus {
  requested_repository_backend: string;
  active_repository_backend: string;
  database_url_configured: boolean;
  repository_ready: boolean;
  requested_queue_backend: string;
  active_queue_backend: string;
  redis_url_configured: boolean;
  queue_ready: boolean;
  client_data_ready: boolean;
  blocking_checks: string[];
}

export interface ApiSignedUrlResponse {
  url: string;
  expires_at: string;
}

export async function getSession(): Promise<ApiSession> {
  return request<ApiSession>("/auth/session");
}

export async function getWorkspaces(): Promise<ApiWorkspace[]> {
  return request<ApiWorkspace[]>("/workspaces");
}

export async function getClientDataReadiness(): Promise<ApiClientDataReadiness> {
  return request<ApiClientDataReadiness>("/readiness/client-data");
}

export async function getLocalAiStatus(): Promise<ApiLocalAiStatus> {
  return request<ApiLocalAiStatus>("/local-ai/status");
}

export async function getRuntimeBackends(): Promise<ApiRuntimeBackendStatus> {
  return request<ApiRuntimeBackendStatus>("/runtime/backends");
}

export async function askChat(workspaceId: string, content: string): Promise<ApiChatResponse> {
  return request<ApiChatResponse>("/chat/messages", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: workspaceId,
      content,
      filters: {}
    })
  });
}

export async function getReportDraft(workspaceId: string): Promise<ApiReportDraft> {
  return request<ApiReportDraft>(`/workspaces/${workspaceId}/report-draft`);
}

export async function createUpload(params: {
  workspaceId: string;
  fileName: string;
  byteSize: number;
  mimeType: string;
  sourceType: "zip" | "folder" | "files";
}): Promise<ApiUploadCreateResponse> {
  return request<ApiUploadCreateResponse>("/uploads", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: params.workspaceId,
      file_name: params.fileName,
      byte_size: params.byteSize,
      mime_type: params.mimeType || "application/octet-stream",
      source_type: params.sourceType
    })
  });
}

export async function directUploadFile(params: {
  workspaceId: string;
  file: File;
  fileName: string;
  sourceType: "zip" | "folder" | "files";
}): Promise<ApiUploadCreateResponse> {
  const formData = new FormData();
  formData.append("workspace_id", params.workspaceId);
  formData.append("file_name", params.fileName);
  formData.append("source_type", params.sourceType);
  formData.append("file", params.file, params.file.name);

  return request<ApiUploadCreateResponse>("/uploads/direct", {
    method: "POST",
    body: formData
  });
}

export async function completeUpload(uploadId: string, fileIds: string[]): Promise<{ upload_id: string; status: string }> {
  return request<{ upload_id: string; status: string }>(`/uploads/${uploadId}/complete`, {
    method: "POST",
    body: JSON.stringify({ file_ids: fileIds })
  });
}

export async function getAuditLogs(limit = 20): Promise<ApiAuditLog[]> {
  return request<ApiAuditLog[]>(`/audit-logs?limit=${limit}`);
}

export async function getAuditIntegrity(): Promise<ApiAuditIntegrityStatus> {
  return request<ApiAuditIntegrityStatus>("/audit-logs/integrity");
}

export async function getProcessingJobs(): Promise<ApiProcessingJob[]> {
  return request<ApiProcessingJob[]>("/processing-jobs");
}

export async function getDocuments(): Promise<ApiParsedDocument[]> {
  return request<ApiParsedDocument[]>("/documents");
}

export async function getFailures(): Promise<ApiFailureRecord[]> {
  return request<ApiFailureRecord[]>("/failures");
}

export async function getValidationTasks(): Promise<ApiValidationTask[]> {
  return request<ApiValidationTask[]>("/validation-tasks");
}

export async function updateValidationTask(params: {
  taskId: string;
  status: ApiValidationTask["status"];
  resolutionNote?: string;
}): Promise<ApiValidationTask> {
  return request<ApiValidationTask>(`/validation-tasks/${params.taskId}`, {
    method: "PATCH",
    body: JSON.stringify({
      status: params.status,
      resolution_note: params.resolutionNote ?? null
    })
  });
}

export async function createMondayReport(params: {
  workspaceId: string;
  periodStart: string;
  periodEnd: string;
}): Promise<ApiMondayReport> {
  return request<ApiMondayReport>("/monday-reports", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: params.workspaceId,
      period_start: params.periodStart,
      period_end: params.periodEnd
    })
  });
}

export async function getMondayReports(workspaceId?: string): Promise<ApiMondayReport[]> {
  const query = workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : "";
  return request<ApiMondayReport[]>(`/monday-reports${query}`);
}

export async function exportMondayReport(
  reportId: string,
  format: ApiReportExport["format"],
  options: ExportMondayReportOptions = {}
): Promise<ApiReportExport> {
  const query = options.allowUnresolvedValidation ? "?allow_unresolved_validation=true" : "";
  return request<ApiReportExport>(`/monday-reports/${reportId}/exports/${format}${query}`, {
    method: "POST"
  });
}

export async function createReportExportSignedUrl(exportId: string): Promise<ApiSignedUrlResponse> {
  return request<ApiSignedUrlResponse>(`/report-exports/${exportId}/signed-url`, {
    method: "POST"
  });
}

export async function createUploadFileSignedUrl(fileId: string): Promise<ApiSignedUrlResponse> {
  return request<ApiSignedUrlResponse>(`/upload-files/${fileId}/signed-url`, {
    method: "POST"
  });
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const isMultipart = init.body instanceof FormData;
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(isMultipart ? {} : { "Content-Type": "application/json" }),
      ...(API_KEY ? { "X-Monday-Report-Key": API_KEY } : {}),
      ...init.headers
    }
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (typeof payload.detail === "string") {
        detail = payload.detail;
      } else if (payload.detail) {
        detail = JSON.stringify(payload.detail);
      }
    } catch {
      detail = response.statusText;
    }
    throw new Error(`API ${response.status}: ${detail}`);
  }

  return response.json() as Promise<T>;
}
