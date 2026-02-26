import { invoke } from "@tauri-apps/api/core";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type PiiCategory =
  | "email"
  | "phone"
  | "iban"
  | "credit_card"
  | "ip_address"
  | "address"
  | "postal_code"
  | "date_of_birth"
  | "cookie"
  | "user_id"
  | "secret"
  | "file_name_signal"
  | "weak_archive_encryption";

export type PiiFinding = {
  category: string;
  count: number;
  redacted_examples: string[];
};

export type CustomFinding = {
  category: string;
  count: number;
  redacted_examples: string[];
};

export type UiAlert = {
  file_id: number;
  path: string;
  first_seen_at: number;
  last_seen_at: number;
  size: number;
  mtime: number;
  risk_level: RiskLevel;
  risk_score: number;
  pii_summary: PiiFinding[];
  custom_summary: CustomFinding[];
  weak_zip_encryption: boolean;
  ignored: boolean;
  deleted: boolean;
};

export type RevealedCategory = {
  category: string;
  values: { value: string; is_ignored: boolean }[];
};

export type Report = {
  file_id: number;
  path: string;
  first_seen_at: number;
  last_seen_at: number;
  size: number;
  mtime: number;
  risk_level: RiskLevel;
  risk_score: number;
  reasons: { key: string; vars: Record<string, unknown> }[];
  findings: PiiFinding[];
  custom_findings: CustomFinding[];
  weak_zip_encryption: boolean;
  suggestion: string;
  revealed?: { by_category: RevealedCategory[] } | null;
};

export type Settings = {
  watched_directories: string[];
  ignored_extensions: string[];
  max_file_bytes: number;
  max_text_bytes: number;
  max_zip_total_uncompressed_bytes: number;
  max_zip_entry_bytes: number;
  max_zip_entries: number;
  max_zip_depth: number;
  reminders_hours: number;
  reminders_days_7: number;
  reminders_days_30: number;
};

export type CustomDetector = {
  id: number;
  name: string;
  risk_level: RiskLevel;
  filename_regex?: string | null;
  field_name_regex?: string | null;
  value_regex?: string | null;
  enabled: boolean;
  created_at: number;
  updated_at: number;
};

export type NewCustomDetector = {
  name: string;
  risk_level: RiskLevel;
  filename_regex?: string | null;
  field_name_regex?: string | null;
  value_regex?: string | null;
  enabled: boolean;
};

export async function listAlerts(): Promise<UiAlert[]> {
  return invoke("list_alerts");
}

export async function getReport(fileId: number, reveal: boolean): Promise<Report> {
  return invoke("get_report", { fileId, reveal });
}

export async function ignoreFile(fileId: number): Promise<void> {
  await invoke("ignore_file", { fileId });
}

export async function unignoreFile(fileId: number): Promise<void> {
  await invoke("unignore_file", { fileId });
}

export async function deleteFileToTrash(fileId: number): Promise<void> {
  await invoke("delete_file_to_trash", { fileId });
}

export async function neutralizeFile(fileId: number): Promise<number> {
  return invoke("neutralize_file", { fileId });
}

export async function openInFileManager(path: string): Promise<void> {
  await invoke("open_in_file_manager", { path });
}

export async function scanNow(): Promise<void> {
  await invoke("scan_now");
}

export async function stopScan(): Promise<void> {
  await invoke("stop_scan");
}

export async function clearAlerts(): Promise<void> {
  await invoke("clear_alerts");
}

export async function listCustomDetectors(): Promise<CustomDetector[]> {
  return invoke("list_custom_detectors");
}

export async function createCustomDetector(input: NewCustomDetector): Promise<CustomDetector> {
  return invoke("create_custom_detector", { input });
}

export async function updateCustomDetector(id: number, input: NewCustomDetector): Promise<void> {
  await invoke("update_custom_detector", { id, input });
}

export async function deleteCustomDetector(id: number): Promise<void> {
  await invoke("delete_custom_detector", { id });
}

export async function getSettings(): Promise<Settings> {
  return invoke("get_settings");
}

export async function setSettings(settings: Settings): Promise<void> {
  await invoke("set_settings", { settings });
}

export async function ignoreValue(category: string, value: string): Promise<void> {
  await invoke("ignore_value", { category, value });
}

export async function unignoreValue(category: string, value: string): Promise<void> {
  await invoke("unignore_value", { category, value });
}

export type EntitySetting = {
  entity_type: string;
  entity_category: "pure" | "contextual";
  enabled: boolean;
  locale_requirement: string | null;
  positive_indicators: string | null;
  negative_indicators: string | null;
  threshold: number | null;
};

export type TypeDefinition = {
  id: string;
  display_name_key: string;
  description_key: string;
  category: string;
  risk_level: RiskLevel;
  requires_key: boolean;
  key_labels: string[];
  advanced: TypeAdvanced;
  enabled: boolean;
  locale_requirement: string | null;
  positive_indicators: string | null;
  negative_indicators: string | null;
  threshold: number | null;
  origin: string;
  filename_regex?: string | null;
  field_name_regex?: string | null;
  value_regex?: string | null;
};

export type TypeAdvanced = {
  blocked_extensions: string[];
  filename_keywords: FilenameKeyword[];
};

export type FilenameKeyword = {
  keyword: string;
  score: number;
};

export type AgentsMode = "agent" | "server";

export type AgentsState = {
  mode: AgentsMode;
  server_listen_addr: string | null;
  paired_server_url: string | null;
  paired_at: number | null;
  pair_expires_at: number | null;
  pair_expired: boolean;
  server_pair_code: string | null;
  server_pair_code_expires_at: number | null;
};

export async function getEntitySettings(): Promise<EntitySetting[]> {
  return invoke("get_entity_settings");
}

export async function updateEntityEnabled(entityType: string, enabled: boolean): Promise<void> {
  await invoke("update_entity_enabled", { entityType, enabled });
}

export async function updateContextualEntity(
  entityType: string,
  positiveIndicators: string | null,
  negativeIndicators: string | null,
  threshold: number | null,
): Promise<void> {
  await invoke("update_contextual_entity", {
    entityType,
    positiveIndicators,
    negativeIndicators,
    threshold,
  });
}

export async function listTypeDefinitions(): Promise<TypeDefinition[]> {
  return invoke("list_type_definitions");
}

export async function reloadTypeCatalog(): Promise<string> {
  return invoke("reload_type_catalog");
}

export async function upsertCustomTypeDefinition(input: TypeDefinition): Promise<string> {
  return invoke("upsert_custom_type_definition", { input });
}

export async function getAgentsState(): Promise<AgentsState> {
  return invoke("get_agents_state");
}

export async function setAgentsMode(mode: AgentsMode): Promise<AgentsState> {
  return invoke("set_agents_mode", { mode });
}

export async function createServerPairCode(validMinutes = 30): Promise<AgentsState> {
  return invoke("create_server_pair_code", { validMinutes });
}

export async function pairAsAgent(
  serverUrl: string,
  code: string,
  internetConfirmed: boolean,
  validDays = 14,
): Promise<AgentsState> {
  return invoke("pair_as_agent", {
    serverUrl,
    code,
    internetConfirmed,
    validDays,
  });
}

export async function unpairAgent(): Promise<AgentsState> {
  return invoke("unpair_agent");
}
