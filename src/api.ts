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
  values: { value: string; is_mine: boolean }[];
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

export async function markValueAsMine(category: string, value: string): Promise<void> {
  await invoke("mark_value_as_mine", { category, value });
}

export async function unmarkValueAsMine(category: string, value: string): Promise<void> {
  await invoke("unmark_value_as_mine", { category, value });
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
