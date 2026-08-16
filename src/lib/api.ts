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
  // Additive identity-foundation fields (optional for backward compatibility).
  account_status?: "active" | "disabled";
  is_bootstrap?: boolean;
}

// Request-scoped authenticated identity (no secret material). `demo_bootstrap`
// is the explicit local/compatibility identity, not a verified per-user one.
export interface ApiAuthenticatedIdentity {
  user_id: string;
  tenant_id: string;
  email: string;
  display_name: string;
  roles: string[];
  account_status: "active" | "disabled";
  authentication_source: "api_token" | "shared_key_bootstrap" | "system";
  credential_id?: string | null;
  credential_fingerprint?: string | null;
  actor_source: "authenticated" | "demo_bootstrap" | "system";
}

export interface ApiSession {
  tenant: ApiTenant;
  user: ApiUser;
  // Additive identity context; older clients ignore these.
  authenticated_identity?: ApiAuthenticatedIdentity | null;
  permissions?: Record<string, boolean>;
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

export interface ApiCasingString {
  name: string;
  od?: string | null;
  top_ft?: number | null;
  shoe_ft?: number | null;
  status?: string | null;
  source: "source" | "reference";
  page?: number | null;
  confidence?: number | null;
}

export interface ApiActivitySegment {
  time: string;
  activity: string;
  source: "source" | "reference";
  page?: number | null;
  confidence?: number | null;
}

export interface ApiSurveyStation {
  measured_depth_ft: number;
  inclination_deg?: number | null;
  azimuth_deg?: number | null;
  true_vertical_depth_ft?: number | null;
  dogleg_severity_dp100ft?: number | null;
  north_south_ft?: number | null;
  east_west_ft?: number | null;
  station_id?: string | null;
  survey_type?: string | null;
  source: "source";
  page?: number | null;
  confidence?: number | null;
  conflict?: boolean;
}

export type ApiTrajectoryReferenceMode = "source_absolute" | "relative_first_station" | "none";

export interface ApiTrajectoryCoordinateReference {
  tvd: ApiTrajectoryReferenceMode;
  north_south: ApiTrajectoryReferenceMode;
  east_west: ApiTrajectoryReferenceMode;
}

export interface ApiTrajectoryAnchor {
  measured_depth_ft: number;
  tvd_ft?: number | null;
  north_south_ft?: number | null;
  east_west_ft?: number | null;
  source_page?: number | null;
}

export interface ApiTrajectoryInterval {
  md_start_ft: number;
  md_end_ft: number;
  start_station_id?: string | null;
  end_station_id?: string | null;
  survey_type?: string | null;
  segment: number;
  dogleg_deg: number;
  dls_deg_per_100ft: number;
  ratio_factor: number;
  delta_tvd_ft: number;
  delta_ns_ft: number;
  delta_ew_ft: number;
  source_pages: number[];
  input_confidence_min?: number | null;
  source: "calculated";
  method: "minimum_curvature";
  method_version: string;
}

export interface ApiCalculatedTrajectoryStation {
  measured_depth_ft: number;
  tvd_ft: number;
  north_south_ft: number;
  east_west_ft: number;
  horizontal_displacement_ft: number;
  source_station_id?: string | null;
  source_page?: number | null;
  segment: number;
  survey_type?: string | null;
  coordinate_reference: ApiTrajectoryCoordinateReference;
  source: "calculated";
}

export interface ApiTrajectorySkipSummary {
  conflict: number;
  missing_inclination: number;
  missing_azimuth: number;
  invalid_numeric: number;
  zero_md_interval: number;
  decreasing_md: number;
  survey_type_boundary: number;
  antipodal_singularity: number;
  truncated: number;
}

export interface ApiTrajectoryCalculation {
  method: "minimum_curvature";
  method_version: string;
  review_state: "review_required";
  coordinate_reference: ApiTrajectoryCoordinateReference;
  anchor?: ApiTrajectoryAnchor | null;
  source_station_count: number;
  eligible_station_count: number;
  segment_count: number;
  interval_count: number;
  intervals: ApiTrajectoryInterval[];
  stations: ApiCalculatedTrajectoryStation[];
  skips: ApiTrajectorySkipSummary;
  input_confidence_min?: number | null;
}

export type ApiHydraulicMeasurement =
  | "flow_rate"
  | "standpipe_pressure"
  | "mud_weight"
  | "ecd"
  | "plastic_viscosity"
  | "yield_point"
  | "pump_rate"
  | "nozzle_configuration";

export interface ApiHydraulicObservation {
  measurement: ApiHydraulicMeasurement;
  value?: number | null;
  unit?: string | null;
  source_value_text: string;
  source_unit?: string | null;
  observation_status: "observed" | "planned" | "unknown";
  equipment_label?: string | null;
  fluid_system_label?: string | null;
  context_note?: string | null;
  activity_time?: string | null;
  activity_time_source_text?: string | null;
  parser_method: "deterministic_hydraulics";
  parser_version: string;
  source: "source";
  page?: number | null;
  confidence?: number | null;
  conflict?: boolean;
  review_flag?: boolean;
  review_reason?: string | null;
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
  casing_strings?: ApiCasingString[];
  activity_timeline?: ApiActivitySegment[];
  schematic_source?: "source" | "reference";
  survey_stations?: ApiSurveyStation[];
  survey_source?: "source" | "none";
  trajectory?: ApiTrajectoryCalculation | null;
  trajectory_source?: "calculated" | "none";
  hydraulics_observations?: ApiHydraulicObservation[];
  hydraulics_source?: "source" | "none";
  field_corrections?: ApiFieldCorrection[];
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
  // Additive keyed-integrity envelope: a v2 event sets integrity_version=2 and
  // records the HMAC algorithm + key id/version; legacy (unkeyed SHA-256) events
  // leave these null. Legacy consumers ignore them.
  integrity_version?: number | null;
  integrity_algorithm?: string | null;
  key_id?: string | null;
  key_version?: number | null;
}

export interface ApiAuditIntegrityStatus {
  // `status` is additive-preserved: "sealed" means the hash chain is intact
  // (keyed OR legacy) — NOT a claim of keying. The keyed distinction lives in
  // `integrity_state` and the counts below.
  status: "empty" | "sealed" | "legacy" | "broken";
  total_events: number;
  hashed_events: number;
  legacy_events: number;
  broken_events: number;
  latest_hash?: string | null;
  detail: string;
  // Additive versioned-integrity view (legacy consumers ignore these).
  // legacy_valid/mixed_valid are NOT fully keyed.
  integrity_state?:
    | "empty"
    | "legacy_valid"
    | "mixed_valid"
    | "keyed_valid"
    | "broken"
    | "key_unavailable"
    | null;
  legacy_event_count?: number;
  keyed_event_count?: number;
  active_key_id?: string | null;
  active_key_version?: number | null;
  unknown_key_versions?: string[];
  first_broken_event_id?: string | null;
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
  target_type: "failure" | "npt_event" | "company" | "tool" | "citation" | "file" | "anomaly_event" | "ai_statement";
  target_id: string;
  reason: string;
  priority: "low" | "medium" | "high" | "critical";
  status: "open" | "validated" | "rejected" | "conflict";
  resolution_note?: string | null;
  // Verified-reviewer attribution (AUDIT-001), server-derived (see ApiFieldCorrection).
  reviewer_user_id?: string | null;
  reviewer_credential_id?: string | null;
  reviewer_credential_fingerprint?: string | null;
  reviewer_roles?: string[];
  reviewer_actor_source?: "configured" | "authenticated" | "demo_bootstrap" | "system" | null;
  reviewer_verified_at?: string | null;
  created_at: string;
}

export type ApiFieldCorrectionTargetType =
  | "report_field"
  | "casing_string"
  | "survey_station"
  | "hydraulics_observation"
  | "activity_segment"
  | "failure";

export interface ApiFieldCorrection {
  id: string;
  tenant_id: string;
  workspace_id: string;
  target_type: ApiFieldCorrectionTargetType;
  field_key: string;
  source_value?: string | null;
  corrected_value?: string | null;
  correction_reason: string;
  actor_user_id: string;
  actor_email: string;
  actor_roles: string[];
  actor_source: "configured" | "authenticated" | "demo_bootstrap" | "system";
  actor_credential_fingerprint?: string | null;
  status: "active" | "superseded" | "reverted";
  supersedes_id?: string | null;
  superseded_by_id?: string | null;
  revert_reason?: string | null;
  // Verified-reviewer attribution (AUDIT-001), server-derived. reviewer_verified_at
  // is set only for a verified authenticated human; a demo action leaves it null.
  reviewer_user_id?: string | null;
  reviewer_credential_id?: string | null;
  reviewer_credential_fingerprint?: string | null;
  reviewer_roles?: string[];
  reviewer_actor_source?: "configured" | "authenticated" | "demo_bootstrap" | "system" | null;
  reviewer_verified_at?: string | null;
  revert_reviewer_user_id?: string | null;
  revert_reviewer_credential_fingerprint?: string | null;
  revert_reviewer_roles?: string[];
  revert_reviewer_actor_source?: "configured" | "authenticated" | "demo_bootstrap" | "system" | null;
  revert_reviewer_verified_at?: string | null;
  created_at: string;
}

export interface ApiFieldCorrectionCreate {
  target_type: ApiFieldCorrectionTargetType;
  field_key: string;
  source_value?: string | null;
  corrected_value?: string | null;
  correction_reason: string;
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

export interface ApiBenchmarkValue {
  id: string;
  tenant_id: string;
  benchmark_name: string;
  metric: string;
  value: number;
  unit: string;
  performance_category: string;
  data_source: string;
  effective_date: string;
  dataset_version: string;
  last_updated: string;
  approval_status: "draft" | "approved" | "retired";
}

export interface ApiAnomalyRule {
  id: string;
  tenant_id: string;
  name: string;
  metric: string;
  severity: "Advisory" | "Warning" | "Critical";
  benchmark_name: string;
  threshold_mode: "below_benchmark" | "below_percent_of_benchmark";
  threshold_percent?: number | null;
  diagnostic_modules: string[];
  approval_status: "draft" | "approved" | "retired";
  last_updated: string;
}

export interface ApiBenchmarkComparison {
  metric: string;
  benchmark_name: string;
  current_value?: number | null;
  current_unit: string;
  benchmark_value?: number | null;
  benchmark_unit: string;
  absolute_variance?: number | null;
  percentage_variance?: number | null;
  performance_status:
    | "Above benchmark"
    | "Within expected range"
    | "Below benchmark"
    | "Critical deviation"
    | "Insufficient data"
    | "Stale data";
  supporting_source: string;
  data_timestamp?: string | null;
  confidence_status: string;
}

export interface ApiDiagnosticAction {
  id: string;
  module: "Hydraulics" | "Torque & Drag";
  status: "Recommended" | "Queued" | "Running" | "Completed" | "Failed" | "Dismissed";
  reason: string;
  authorized_user?: string | null;
  timestamp: string;
  dismissal_reason?: string | null;
}

export interface ApiAnomalyEvent {
  id: string;
  tenant_id: string;
  workspace_id: string;
  measurement_id?: string | null;
  metric: string;
  severity: "Advisory" | "Warning" | "Critical";
  performance_status: string;
  current_value: number;
  unit: string;
  threshold_value: number;
  threshold_unit: string;
  rule_id: string;
  rule_name: string;
  summary: string;
  benchmark_evidence: Record<string, unknown>;
  supporting_citations: ApiCitation[];
  diagnostic_actions: ApiDiagnosticAction[];
  moc_reference?: string | null;
  status: "active" | "dismissed" | "resolved";
  created_at: string;
}

export interface ApiAiReportStatement {
  category:
    | "Measured fact"
    | "Calculated result"
    | "Inferred explanation"
    | "Risk assessment"
    | "Recommended action";
  text: string;
  review_status: "review_required" | "accepted" | "rejected";
  source_reference?: string | null;
}

export interface ApiBenchmarkingStatus {
  workspace_id: string;
  generated_at: string;
  current_ft_per_day?: number | null;
  seven_day_average_ft_per_day?: number | null;
  gordon_average_benchmark?: number | null;
  noble_top_quartile_benchmark?: number | null;
  comparisons: ApiBenchmarkComparison[];
  active_anomalies: ApiAnomalyEvent[];
  historical_anomalies: ApiAnomalyEvent[];
  benchmark_values: ApiBenchmarkValue[];
  anomaly_rules: ApiAnomalyRule[];
  seven_day_trend: {
    timestamp: string;
    value: number;
    unit: string;
    confidence_status: string;
  }[];
  likely_operational_contributors: string[];
  recommended_diagnostic_actions: ApiDiagnosticAction[];
  supporting_evidence_references: string[];
  ai_interpretation: ApiAiReportStatement[];
  permissions: Record<string, boolean>;
}

export interface ApiBenchmarkConfig {
  benchmark_values: ApiBenchmarkValue[];
  anomaly_rules: ApiAnomalyRule[];
  permissions: Record<string, boolean>;
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

export type ApiReadinessDisposition =
  | "PASS"
  | "FAIL"
  | "BLOCKED"
  | "SKIPPED"
  | "NOT_APPLICABLE"
  | "REVIEW_REQUIRED";

export type ApiReadinessCategory =
  | "software"
  | "configuration"
  | "infrastructure"
  | "security_review"
  | "data_review_evidence"
  | "client_approval";

export interface ApiClientDataReadinessCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  remediation: string;
  // Additive, optional GA-integrity metadata (legacy consumers ignore these).
  disposition?: ApiReadinessDisposition | null;
  category?: ApiReadinessCategory | null;
  severity?: "blocker" | "high" | "medium" | "low" | null;
  owner_type?:
    | "engineering"
    | "security"
    | "platform"
    | "operations"
    | "data_review"
    | "client_organization"
    | null;
  policy_reference?: string | null;
  evidence_reference?: string | null;
  resolution_condition?: string | null;
  applicability_justification?: string | null;
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
  // Which provider actually answers right now, from the server-side resolver's decision
  // (not reachability): "deterministic" (built-in analysis) or "local-model".
  active_provider?: string;
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

// Chat-role-readable provenance: which engine writes answers right now.
export interface ApiProviderStatus {
  active_provider: string; // "deterministic" | "local-model" | "online-api"
}

// Non-secret view of the optional Online AI config. The API key is NEVER returned —
// only `has_key` reports whether one is stored.
export interface ApiOnlineConfig {
  configured: boolean;
  provider?: string | null;
  base_url?: string | null;
  model?: string | null;
  has_key: boolean;
  updated_at?: string | null;
  storage_available: boolean;
  detail: string;
}

export interface ApiOnlineSettingsInput {
  provider: string;
  base_url: string;
  model: string;
  api_key: string;
}

export interface ApiOnlineTestResult {
  status: string; // connected | auth_failed | rate_limited | unavailable | misconfigured
  detail: string;
}

export async function getProviderStatus(): Promise<ApiProviderStatus> {
  return request<ApiProviderStatus>("/ai/provider-status");
}

export async function getOnlineConfig(): Promise<ApiOnlineConfig> {
  return request<ApiOnlineConfig>("/online-ai/config");
}

export async function saveOnlineConfig(input: ApiOnlineSettingsInput): Promise<ApiOnlineConfig> {
  return request<ApiOnlineConfig>("/online-ai/config", { method: "POST", body: JSON.stringify(input) });
}

export async function removeOnlineConfig(): Promise<ApiOnlineConfig> {
  return request<ApiOnlineConfig>("/online-ai/config", { method: "DELETE" });
}

export async function testOnlineConnection(input: ApiOnlineSettingsInput): Promise<ApiOnlineTestResult> {
  return request<ApiOnlineTestResult>("/online-ai/test-connection", { method: "POST", body: JSON.stringify(input) });
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

export async function getBenchmarkConfig(): Promise<ApiBenchmarkConfig> {
  return request<ApiBenchmarkConfig>("/benchmarking/config");
}

export async function getWorkspaceBenchmarking(workspaceId: string): Promise<ApiBenchmarkingStatus> {
  return request<ApiBenchmarkingStatus>(`/workspaces/${workspaceId}/benchmarking`);
}

export async function createBenchmarkMeasurement(params: {
  workspaceId: string;
  metric: string;
  value: number;
  unit: string;
  dataSource: string;
  confidenceStatus?: "high" | "medium" | "low" | "manual" | "stale" | "conflicting" | "missing";
  sourceType?: string;
  sourceIdentifier?: string;
  datasetVersion?: string;
  mocReference?: string;
}): Promise<ApiBenchmarkingStatus> {
  return request<ApiBenchmarkingStatus>(`/workspaces/${params.workspaceId}/benchmarking/measurements`, {
    method: "POST",
    body: JSON.stringify({
      metric: params.metric,
      value: params.value,
      unit: params.unit,
      data_source: params.dataSource,
      confidence_status: params.confidenceStatus ?? "manual",
      source_type: params.sourceType ?? "manual",
      source_identifier: params.sourceIdentifier ?? "manual-entry",
      dataset_version: params.datasetVersion ?? "manual-v1",
      moc_reference: params.mocReference ?? null
    })
  });
}

export async function updateBenchmarkValue(params: {
  benchmarkId: string;
  value?: number;
  unit?: string;
  performanceCategory?: string;
  dataSource?: string;
  datasetVersion?: string;
  approvalStatus?: "draft" | "approved" | "retired";
  reason: string;
}): Promise<ApiBenchmarkValue> {
  return request<ApiBenchmarkValue>(`/benchmarking/values/${params.benchmarkId}`, {
    method: "PATCH",
    body: JSON.stringify({
      value: params.value ?? null,
      unit: params.unit ?? null,
      performance_category: params.performanceCategory ?? null,
      data_source: params.dataSource ?? null,
      dataset_version: params.datasetVersion ?? null,
      approval_status: params.approvalStatus ?? null,
      reason: params.reason
    })
  });
}

export async function dismissBenchmarkDiagnostic(params: {
  anomalyId: string;
  actionId: string;
  reason: string;
}): Promise<ApiAnomalyEvent> {
  return request<ApiAnomalyEvent>(
    `/benchmarking/anomalies/${params.anomalyId}/diagnostics/${params.actionId}/dismiss`,
    {
      method: "PATCH",
      body: JSON.stringify({ reason: params.reason })
    }
  );
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

export async function recordFieldCorrection(
  workspaceId: string,
  payload: ApiFieldCorrectionCreate
): Promise<ApiFieldCorrection> {
  return request<ApiFieldCorrection>(`/workspaces/${workspaceId}/field-corrections`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function listFieldCorrections(
  workspaceId: string,
  activeOnly = false
): Promise<ApiFieldCorrection[]> {
  const query = activeOnly ? "?active_only=true" : "";
  return request<ApiFieldCorrection[]>(`/workspaces/${workspaceId}/field-corrections${query}`);
}

export async function revertFieldCorrection(
  correctionId: string,
  revertReason: string
): Promise<ApiFieldCorrection> {
  return request<ApiFieldCorrection>(`/field-corrections/${correctionId}/revert`, {
    method: "POST",
    body: JSON.stringify({ revert_reason: revertReason })
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

function newIdempotencyKey(): string {
  const c: Crypto | undefined = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") {
    return `ui-${c.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  c?.getRandomValues?.(bytes);
  return `ui-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const isMultipart = init.body instanceof FormData;
  const method = (init.method ?? "GET").toUpperCase();
  // Mutating requests carry an Idempotency-Key: the PostgreSQL store REQUIRES it on
  // transactional operations (validation-task transitions, correction record/revert)
  // and non-transactional routes ignore it. One user action = one call = one key; a
  // caller may override via init.headers so a retry of the same action reuses the key.
  const isMutation = method !== "GET" && method !== "HEAD";
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(isMultipart ? {} : { "Content-Type": "application/json" }),
      ...(API_KEY ? { "X-Monday-Report-Key": API_KEY } : {}),
      ...(isMutation ? { "Idempotency-Key": newIdempotencyKey() } : {}),
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

// ── Offline license (the localhost wrapper that serves this SPA) ───────────────
// These endpoints live on the offline-runtime wrapper, NOT the workspace API, so
// they use a BARE relative URL — in the packaged product the wrapper serves both
// the SPA document and /offline/license/* on one loopback origin, so a relative
// fetch reaches the wrapper. They carry no workspace credential (the wrapper does
// not require one). In a dev/standalone setup the wrapper is absent and the SPA's
// dev server answers these with its index.html fallback, so `.json()` rejects and
// the caller treats the license as UNOBSERVABLE rather than inventing a state.

export interface LicenseStatus {
  state: string;
  reason_code: string;
  edition: string;
  read_only: boolean;
  issued_at: string | null;
  not_before: string | null;
  expires_at: string | null;
  grace_until: string | null;
  renewal_sequence: number;
  license_id: string | null;
  support_code: string;
  product_version: string;
  feature_flags: Record<string, boolean>;
  machine_binding?: {
    fingerprint_version: string;
    eligible_components: number;
    binding_confidence: string;
    match: string;
  };
}

export interface LicenseImportResult {
  imported: boolean;
  state?: string;
  expires_at?: string | null;
  reason_code?: string;
  detail?: string;
}

/** The wrapper route that streams this machine's activation request (hashed machine
 *  facts only). Rendered as a download link; the wrapper sets Content-Disposition. */
export const LICENSE_ACTIVATION_REQUEST_PATH = "/offline/license/activation-request";

/** Read the machine's license status from the offline-runtime wrapper. Rejects when
 *  the wrapper is not present (dev/standalone), which the caller surfaces as
 *  "license status unavailable here" — never a fabricated state. */
export async function getLicenseStatus(): Promise<LicenseStatus> {
  const response = await fetch("/offline/license/status", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`license status ${response.status}`);
  // A dev SPA (no wrapper) returns index.html here; json() then throws, which the
  // caller treats as "license unobservable in this environment".
  return (await response.json()) as LicenseStatus;
}

/** Import a signed license file through the wrapper. The body is the raw license
 *  JSON the operator selected; the wrapper performs the DPAPI-protected,
 *  machine-bound validation on this computer. Returns the parsed result for BOTH
 *  success (200) and refusal (400/503) so the caller can report the reason. */
export async function importLicense(licenseJson: string): Promise<LicenseImportResult> {
  const response = await fetch("/offline/license/import", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: licenseJson
  });
  // The documented outcomes (200/400/503) are all JSON. Guard the parse so a
  // reachable-but-erroring wrapper (an unexpected 500, a proxy error page) is
  // reported as a refusal with its status, not misread by the caller as an absent
  // service — only a rejected fetch (below the caller) means genuinely unreachable.
  try {
    return (await response.json()) as LicenseImportResult;
  } catch {
    return {
      imported: false,
      detail: `The license service returned an unreadable response (HTTP ${response.status}).`
    };
  }
}
