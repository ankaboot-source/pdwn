import { listen } from "@tauri-apps/api/event";
import { documentDir, downloadDir, homeDir } from "@tauri-apps/api/path";
import { open } from "@tauri-apps/plugin-dialog";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";
import pdwnWordmark from "../assets/pdwn-wordmark.png";
import aboutMarkdown from "./content/about.md?raw";
import legalMarkdown from "./content/legal.md?raw";
import dependenciesMarkdown from "./content/third-party-notices.md?raw";

import {
  type AgentsMode,
  type AgentsState,
  type Report,
  type ServerAlert,
  type ServerDevice,
  type Settings,
  type TypeDefinition,
  type UiAlert,
  clearAlerts,
  createServerPairCode,
  deleteFileToTrash,
  getAgentsState,
  getReport,
  getServerHostTypesYaml,
  getSettings,
  ignoreFile,
  ignoreValue,
  listAlerts,
  listServerAlerts,
  listServerDevices,
  listTypeDefinitions,
  neutralizeFile,
  openInFileManager,
  pairAsAgent,
  reloadTypeCatalog,
  scanNow,
  scanPathOnDemand as scanPathOnDemandApi,
  setAgentsMode,
  setServerDeviceEnabled,
  setServerHostTypesYaml,
  setSettings,
  stopScan,
  syncHostTypesFromServer,
  unignoreFile,
  unignoreValue,
  unpairAgent,
  unpairServerDevice,
  upsertCustomTypeDefinition,
} from "./api";
import { getLanguage, initI18n, onLanguageChanged, t } from "./i18n";

type AppEvent =
  | { type: "ready" }
  | { type: "scan_started" }
  | { type: "scan_progress"; processed: number; total: number }
  | { type: "scan_finished" }
  | { type: "alert_created"; file_id: number }
  | { type: "reminder_due"; file_id: number; threshold: string }
  | { type: "scan_error"; path: string; error: string };

const appEl = (() => {
  const el = document.querySelector<HTMLDivElement>("#app");
  if (!el) throw new Error("Missing #app");
  return el;
})();

let alerts: UiAlert[] = [];
let appSettings: Settings | null = null;
let selectedFileId: number | null = null;
let selectedReport: Report | null = null;
let showRevealed = false;
let revealLoading = false;
let neutralizeLoading = false;
let reportPanelVisible = true;
let reportLoadError: string | null = null;
let onDemandScanLoading = false;
let reportDropActive = false;
const selectedRiskFilters = new Set<UiAlert["risk_level"]>();
const selectedTypeFilters = new Set<string>();
let selectedDeviceFilter = "all";
let riskFilterOpen = false;
let typeFilterOpen = false;
let sortBy: SortMode = "risk_desc";
let showIgnored = false;
let isScanning = false;
let scanProgress: { processed: number; total: number } | null = null;
let menuOpen = false;
let dialog: "about" | "types" | "agents" | null = null;
let aboutTab: "about" | "legal" = "about";
let legalDependenciesVisible = false;
let typesTab: "standard" | "regional" | "host" | "custom" = "standard";
let typeDefinitions: TypeDefinition[] = [];
let typeDefinitionsLoading = false;
let typeDefinitionsLoaded = false;
let typeDefinitionsError: string | null = null;
let agentsState: AgentsState | null = null;
let agentsLoading = false;
let agentsError: string | null = null;
let serverDevices: ServerDevice[] = [];
let serverAlerts: ServerAlert[] = [];
let serverHostTypesYaml = "types: []\n";
let agentServerUrlInput = "";
let agentPairCodeInput = "";
let agentPairDaysInput = "14";
let typeModal: {
  mode: "view" | "create" | "edit";
  draft: TypeDefinition;
  error: string | null;
  saving: boolean;
} | null = null;

let debugMode = false;

let confirmAction: ConfirmAction | null = null;

const expandedRedacted = new Set<string>();
let alertsListScrollTop = 0;

type SortMode = "risk_desc" | "risk_asc" | "recent" | "type";

type ConfirmAction =
  | { kind: "scanRunning" }
  | { kind: "stopScan" }
  | { kind: "deleteFile"; fileId: number }
  | { kind: "neutralizeFile"; fileId: number }
  | { kind: "clearAll" };

async function onReloadTypes(): Promise<void> {
  try {
    await reloadTypeCatalog();
    await refreshTypeDefinitions();
  } catch (error) {
    typeDefinitionsError = error instanceof Error ? error.message : String(error);
    render();
  }
}

function debugLog(message: string, payload?: unknown): void {
  if (payload === undefined) {
    console.debug(`[pdd] ${message}`);
  } else {
    console.debug(`[pdd] ${message}`, payload);
  }
}

function withIcon(icon: string, text: string): string {
  return `${icon} ${text}`;
}

function exampleKey(category: string, index: number): string {
  return `${category}:${index}`;
}

function getRevealedValue(category: string, index: number): string | null {
  const byCategory = selectedReport?.revealed?.by_category ?? [];
  const match = byCategory.find((c) => c.category === category);
  return match?.values[index]?.value ?? null;
}

async function ensureRevealLoadedForExamples(): Promise<boolean> {
  if (!selectedFileId) return false;
  if (selectedReport?.revealed?.by_category?.length) return true;
  try {
    selectedReport = await getReport(selectedFileId, true);
    reportLoadError = null;
    return true;
  } catch (error) {
    reportLoadError = error instanceof Error ? error.message : String(error);
    return false;
  }
}

function canRevealReport(r: Report): boolean {
  return r.findings.some(
    (f) =>
      f.count > 0 && f.category !== "file_name_signal" && f.category !== "weak_archive_encryption",
  );
}

function canNeutralizeReport(r: Report): boolean {
  const ext = (r.path.split(".").pop() ?? "").toLowerCase();
  return [
    "txt",
    "csv",
    "tsv",
    "json",
    "ndjson",
    "log",
    "md",
    "xml",
    "yaml",
    "yml",
    "html",
    "htm",
    "ini",
    "conf",
  ].includes(ext);
}

async function onScanNow(): Promise<void> {
  if (isScanning) {
    confirmAction = { kind: "scanRunning" };
    render();
    return;
  }
  isScanning = true;
  scanProgress = { processed: 0, total: 0 };
  render();
  try {
    await scanNow();
    await refreshAlerts();
  } finally {
    isScanning = false;
    render();
  }
}

function normalizePathForCompare(path: string): string {
  const normalized = path.trim().replace(/\\/g, "/");
  if (/^[A-Za-z]:\//.test(normalized)) {
    return normalized.toLowerCase();
  }
  return normalized;
}

function filePathFromUri(raw: string): string | null {
  if (!raw.startsWith("file://")) return null;
  try {
    const url = new URL(raw);
    let pathname = decodeURIComponent(url.pathname);
    if (/^\/[A-Za-z]:\//.test(pathname)) {
      pathname = pathname.slice(1);
    }
    return pathname;
  } catch {
    return null;
  }
}

function extractDroppedFilePath(ev: DragEvent): string | null {
  const data = ev.dataTransfer;
  if (!data) return null;

  const files = data.files;
  if (files.length > 0) {
    const file = files[0] as File & { path?: string };
    if (typeof file.path === "string" && file.path.trim().length > 0) {
      return file.path;
    }
  }

  const uriList = data.getData("text/uri-list").trim();
  if (uriList.length > 0) {
    for (const line of uriList.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!candidate || candidate.startsWith("#")) continue;
      const fromUri = filePathFromUri(candidate);
      if (fromUri) return fromUri;
    }
  }

  const plainText = data.getData("text/plain").trim();
  if (plainText.length > 0) {
    const fromUri = filePathFromUri(plainText);
    if (fromUri) return fromUri;
    if (plainText.startsWith("/") || /^[A-Za-z]:[\\/]/.test(plainText)) {
      return plainText;
    }
  }

  return null;
}

async function onScanPathOnDemand(path: string): Promise<void> {
  const normalizedPath = path.trim();
  if (!normalizedPath) {
    reportLoadError = t("report.dropInvalid");
    render();
    return;
  }

  const existingAlert = alerts.find(
    (alert) => normalizePathForCompare(alert.path) === normalizePathForCompare(normalizedPath),
  );
  if (existingAlert) {
    await selectFile(existingAlert.file_id);
    return;
  }

  reportPanelVisible = true;
  selectedFileId = null;
  selectedReport = null;
  showRevealed = false;
  revealLoading = false;
  neutralizeLoading = false;
  expandedRedacted.clear();
  reportLoadError = null;
  onDemandScanLoading = true;
  reportDropActive = false;
  render();

  try {
    selectedReport = await scanPathOnDemandApi(normalizedPath);
  } catch (error) {
    reportLoadError = error instanceof Error ? error.message : String(error);
  } finally {
    onDemandScanLoading = false;
    render();
  }
}

async function onPickFileForOnDemandScan(): Promise<void> {
  const selected = await open({
    directory: false,
    multiple: false,
    title: t("report.dropBrowse"),
  });
  const value = Array.isArray(selected) ? selected[0] : selected;
  if (!value) return;
  await onScanPathOnDemand(value);
}

function renderOnDemandDropzone(): HTMLElement {
  const wrap = el("div", "report-dropzone-wrap");
  const zone = el("div", `report-dropzone${reportDropActive ? " is-active" : ""}`);
  zone.append(el("div", "report-dropzone-title", t("report.dropTitle")));
  zone.append(el("div", "report-dropzone-body", t("report.dropBody")));

  const browseBtn = el("button", "btn btn-mini", t("report.dropBrowse")) as HTMLButtonElement;
  browseBtn.disabled = onDemandScanLoading;
  browseBtn.addEventListener("click", () => void onPickFileForOnDemandScan());
  zone.append(browseBtn);

  if (onDemandScanLoading) {
    const loading = el("div", "report-dropzone-loading");
    loading.append(el("span", "spinner"));
    loading.append(document.createTextNode(t("report.dropLoading")));
    zone.append(loading);
  }

  zone.addEventListener("dragenter", (ev) => {
    ev.preventDefault();
    reportDropActive = true;
    render();
  });
  zone.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    if (!reportDropActive) {
      reportDropActive = true;
      render();
    }
  });
  zone.addEventListener("dragleave", (ev) => {
    const relatedTarget = ev.relatedTarget as Node | null;
    if (relatedTarget && zone.contains(relatedTarget)) {
      return;
    }
    reportDropActive = false;
    render();
  });
  zone.addEventListener("drop", (ev) => {
    ev.preventDefault();
    reportDropActive = false;
    const droppedPath = extractDroppedFilePath(ev);
    if (!droppedPath) {
      reportLoadError = t("report.dropInvalid");
      render();
      return;
    }
    void onScanPathOnDemand(droppedPath);
  });

  wrap.append(zone);
  return wrap;
}

async function saveWatchedDirectories(dirs: string[]): Promise<void> {
  if (!appSettings) return;
  const cleaned = dirs.map((d) => d.trim()).filter((d) => d.length > 0);
  if (cleaned.length === 0) return;
  const next: Settings = {
    ...appSettings,
    watched_directories: Array.from(new Set(cleaned)),
  };
  await setSettings(next);
  appSettings = next;
  await refreshSettings();
  await onScanNow();
}

async function addWatchedDirectory(): Promise<void> {
  const defaultPath = await resolveDefaultDirectoryPickerPath();
  const selected = await open({
    directory: true,
    multiple: true,
    defaultPath,
    title: t("settings.addFolder"),
  });
  if (!selected) return;
  const values = Array.isArray(selected) ? selected : [selected];
  await saveWatchedDirectories([...(appSettings?.watched_directories ?? []), ...values]);
}

async function resolveDefaultDirectoryPickerPath(): Promise<string | undefined> {
  try {
    const d = await downloadDir();
    if (d) return d;
  } catch {
    // ignore
  }
  try {
    const d = await documentDir();
    if (d) return d;
  } catch {
    // ignore
  }
  try {
    const d = await homeDir();
    if (d) return d;
  } catch {
    // ignore
  }
  return undefined;
}

async function editWatchedDirectory(index: number): Promise<void> {
  const current = appSettings?.watched_directories?.[index];
  if (!current) return;
  const selected = await open({
    directory: true,
    multiple: false,
    defaultPath: current,
    title: t("settings.editFolder"),
  });
  const value = Array.isArray(selected) ? selected[0] : selected;
  if (!value) return;
  const dirs = [...(appSettings?.watched_directories ?? [])];
  dirs[index] = value;
  await saveWatchedDirectories(dirs);
}

async function removeWatchedDirectory(index: number): Promise<void> {
  const dirs = [...(appSettings?.watched_directories ?? [])];
  if (dirs.length <= 1) return;
  dirs.splice(index, 1);
  await saveWatchedDirectories(dirs);
}

async function toggleRedactedExample(category: string, index: number): Promise<void> {
  const key = exampleKey(category, index);
  if (expandedRedacted.has(key)) {
    expandedRedacted.delete(key);
    render();
    return;
  }
  const ready = await ensureRevealLoadedForExamples();
  if (!ready) {
    render();
    return;
  }
  if (getRevealedValue(category, index)) {
    expandedRedacted.add(key);
  }
  render();
}

function fmtBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtDate(tsSec: number): string {
  const lang = getLanguage();
  const d = new Date(tsSec * 1000);
  return new Intl.DateTimeFormat(lang, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(d);
}

function fmtAge(tsSec: number): string {
  const lang = getLanguage();
  const now = Date.now();
  const diffSec = Math.max(0, Math.floor((now - tsSec * 1000) / 1000));
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  if (diffSec < 60) return rtf.format(-diffSec, "second");
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return rtf.format(-diffMin, "minute");
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 48) return rtf.format(-diffHr, "hour");
  const diffDay = Math.floor(diffHr / 24);
  return rtf.format(-diffDay, "day");
}

function fileNameFromPath(path: string): string {
  const idx = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return idx >= 0 ? path.slice(idx + 1) : path;
}

function riskLabel(r: UiAlert["risk_level"]): string {
  return t(`risk.${r}`);
}

function riskRank(r: UiAlert["risk_level"]): number {
  const ranks: Record<UiAlert["risk_level"], number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  return ranks[r];
}

function piiLabel(cat: string): string {
  // categories come from rust serde rename_all = snake_case
  const map: Record<string, string> = {
    email: "pii.email",
    phone: "pii.phone",
    iban: "pii.iban",
    credit_card: "pii.creditCard",
    ip_address: "pii.ipAddress",
    address: "pii.address",
    postal_code: "pii.postalCode",
    date_of_birth: "pii.dateOfBirth",
    cookie: "pii.cookie",
    user_id: "pii.userId",
    secret: "pii.secret",
    file_name_signal: "pii.fileNameSignal",
    weak_archive_encryption: "pii.weakArchiveEncryption",
  };
  return t(map[cat] ?? cat);
}

function isBuiltinCategory(cat: string): boolean {
  return [
    "email",
    "phone",
    "iban",
    "credit_card",
    "ip_address",
    "address",
    "postal_code",
    "date_of_birth",
    "cookie",
    "user_id",
    "secret",
    "file_name_signal",
    "weak_archive_encryption",
  ].includes(cat);
}

function categoryLabel(cat: string): string {
  return isBuiltinCategory(cat) ? piiLabel(cat) : cat;
}

function typeDisplayName(def: TypeDefinition): string {
  const translated = t(def.display_name_key);
  return translated === def.display_name_key ? def.display_name_key : translated;
}

function typeDescription(def: TypeDefinition): string {
  const translated = t(def.description_key);
  return translated === def.description_key ? def.description_key : translated;
}

function typeCategoryLabel(cat: string): string {
  const normalized = cat.trim().toLowerCase();
  if (normalized === "pii") return "PII";
  if (normalized === "security") return "Security";
  if (normalized === "sensitive") return "Sensitive";
  return cat;
}

function slugifyId(value: string): string {
  const base = value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_");
  return base || "custom_type";
}

function uniqueTypeIdFromName(name: string): string {
  const base = slugifyId(name);
  if (!typeDefinitions.some((d) => d.id === base)) return base;
  let idx = 2;
  while (typeDefinitions.some((d) => d.id === `${base}_${idx}`)) {
    idx += 1;
  }
  return `${base}_${idx}`;
}

function typeOriginLabel(origin: string): string {
  const map: Record<string, string> = {
    "standard/base": t("types.origin.base"),
    "standard/locale": t("types.origin.locale"),
    host: t("types.origin.host"),
    custom: t("types.origin.custom"),
  };
  return map[origin] ?? origin;
}

function localeParts(locale: string): { lang: string; region: string | null } {
  const normalized = locale.trim().split(".")[0].split("@")[0].replace("_", "-").toLowerCase();
  const [lang = "", region = ""] = normalized.split("-");
  return { lang, region: region || null };
}

function localeRequirementMatches(requirement: string | null | undefined): boolean {
  if (!requirement || !requirement.trim()) return true;
  const runtimeLocale =
    (typeof navigator !== "undefined" && navigator.language) || getLanguage() || "en";
  const req = localeParts(requirement);
  const cur = localeParts(runtimeLocale);

  if (!req.lang || !cur.lang) return false;
  if (req.region) {
    return req.lang === cur.lang && req.region === cur.region;
  }
  if (req.lang.length === 2 && req.lang === cur.lang) return true;
  return cur.region === req.lang;
}

function currentRuntimeLocale(): string {
  const locale = (typeof navigator !== "undefined" && navigator.language) || getLanguage() || "en";
  return locale.replace("_", "-");
}

function typesForTab(tab: "standard" | "regional" | "host" | "custom"): TypeDefinition[] {
  if (tab === "standard") {
    return typeDefinitions.filter((d) => d.origin === "standard/base" && !d.locale_requirement);
  }
  if (tab === "regional") {
    return typeDefinitions.filter(
      (d) =>
        (d.origin === "standard/locale" || Boolean(d.locale_requirement)) &&
        localeRequirementMatches(d.locale_requirement),
    );
  }
  if (tab === "host") {
    return typeDefinitions.filter((d) => d.origin === "host");
  }
  return typeDefinitions.filter((d) => d.origin === "custom");
}

function emptyTypeDraft(): TypeDefinition {
  return {
    id: "",
    display_name_key: "",
    description_key: "",
    category: "pii",
    risk_level: "medium",
    requires_key: false,
    key_labels: [],
    advanced: { blocked_extensions: [], filename_keywords: [] },
    enabled: true,
    locale_requirement: null,
    positive_indicators: null,
    negative_indicators: null,
    threshold: null,
    origin: "custom",
    filename_regex: null,
    field_name_regex: null,
    value_regex: null,
  };
}

function cloneTypeDefinition(def: TypeDefinition): TypeDefinition {
  return {
    ...def,
    key_labels: [...(def.key_labels ?? [])],
    advanced: {
      blocked_extensions: [...(def.advanced?.blocked_extensions ?? [])],
      filename_keywords: [...(def.advanced?.filename_keywords ?? [])],
    },
  };
}

function openCreateTypeModal(): void {
  typeModal = {
    mode: "create",
    draft: emptyTypeDraft(),
    error: null,
    saving: false,
  };
  render();
}

function openViewTypeModal(def: TypeDefinition): void {
  typeModal = {
    mode: def.origin === "custom" ? "edit" : "view",
    draft: cloneTypeDefinition(def),
    error: null,
    saving: false,
  };
  render();
}

function closeTypeModal(): void {
  typeModal = null;
  render();
}

function parseCsv(input: string): string[] {
  return input
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseFilenameKeywords(input: string): TypeDefinition["advanced"]["filename_keywords"] {
  const out: TypeDefinition["advanced"]["filename_keywords"] = [];
  for (const part of input
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)) {
    const [keyword, scoreRaw] = part.split(":").map((s) => s.trim());
    if (!keyword) continue;
    const score = Number(scoreRaw);
    out.push({ keyword, score: Number.isFinite(score) ? score : 5 });
  }
  return out;
}

async function onSaveCustomType(): Promise<void> {
  if (!typeModal || (typeModal.mode !== "create" && typeModal.mode !== "edit")) return;

  const displayName = typeModal.draft.display_name_key.trim();
  const description = typeModal.draft.description_key.trim();
  if (!displayName || !description) {
    typeModal.error = "Name and description are required.";
    render();
    return;
  }

  if (typeModal.mode === "create") {
    typeModal.draft.id = uniqueTypeIdFromName(displayName);
  }
  typeModal.draft.requires_key = typeModal.draft.key_labels.length > 0;
  typeModal.draft.enabled = true;

  const threshold = typeModal.draft.threshold;
  if (threshold !== null && (threshold < 0 || threshold > 1)) {
    typeModal.error = "Threshold must be between 0 and 1.";
    render();
    return;
  }

  typeModal.error = null;
  typeModal.saving = true;
  render();

  try {
    await upsertCustomTypeDefinition({ ...typeModal.draft, origin: "custom" });
    await refreshTypeDefinitions();
    typeModal = null;
    typesTab = "custom";
  } catch (error) {
    if (typeModal) {
      typeModal.error = error instanceof Error ? error.message : String(error);
      typeModal.saving = false;
    }
  }
  render();
}

const RISK_FILTER_OPTIONS: UiAlert["risk_level"][] = ["critical", "high", "medium", "low"];
const BUILTIN_TYPE_FILTER_OPTIONS: string[] = [
  "email",
  "phone",
  "iban",
  "credit_card",
  "ip_address",
  "address",
  "postal_code",
  "date_of_birth",
  "cookie",
  "user_id",
  "secret",
  "weak_archive_encryption",
  "file_name_signal",
];

function toggleSelection<T>(set: Set<T>, value: T): void {
  if (set.has(value)) {
    set.delete(value);
  } else {
    set.add(value);
  }
}

function riskFilterLabel(): string {
  if (selectedRiskFilters.size === 0) return t("filters.all");
  if (selectedRiskFilters.size === 1) {
    const one = Array.from(selectedRiskFilters)[0];
    return riskLabel(one);
  }
  return t("filters.selectedCount", { count: selectedRiskFilters.size });
}

function typeFilterLabel(): string {
  if (selectedTypeFilters.size === 0) return t("filters.all");
  if (selectedTypeFilters.size === 1) {
    const one = Array.from(selectedTypeFilters)[0];
    return categoryLabel(one);
  }
  return t("filters.selectedCount", { count: selectedTypeFilters.size });
}

function summarizeTypes(a: UiAlert | Report): string {
  const findings = "pii_summary" in a ? a.pii_summary : a.findings;
  const customFindings = "custom_summary" in a ? a.custom_summary : a.custom_findings;
  const parts = findings
    .filter((f) => f.count > 0)
    .filter((f) => f.category !== "file_name_signal")
    .slice(0, 4)
    .map((f) => `${categoryLabel(f.category)} (${f.count})`);
  for (const c of customFindings.filter((f) => f.count > 0).slice(0, 3)) {
    parts.push(`${c.category} (${c.count})`);
  }
  if (a.weak_zip_encryption) {
    parts.unshift(piiLabel("weak_archive_encryption"));
  }
  return parts.join(", ");
}

type AlertListItem = { kind: "local"; local: UiAlert } | { kind: "server"; remote: ServerAlert };

function isServerMode(): boolean {
  return agentsState?.mode === "server";
}

function isAgentPaired(): boolean {
  return (
    agentsState?.mode === "agent" &&
    Boolean(agentsState.paired_server_url) &&
    !agentsState.pair_expired
  );
}

function alertHasType(item: AlertListItem, type: string): boolean {
  if (item.kind === "local") {
    if (type === "weak_archive_encryption") return item.local.weak_zip_encryption;
    return (
      item.local.pii_summary.some((f) => f.category === type && f.count > 0) ||
      item.local.custom_summary.some((f) => f.category === type && f.count > 0)
    );
  }
  if (type === "weak_archive_encryption") {
    return item.remote.types.includes(type);
  }
  return item.remote.types.includes(type);
}

function primaryType(item: AlertListItem): string {
  if (item.kind === "local") {
    if (item.local.weak_zip_encryption) return piiLabel("weak_archive_encryption");
    const top = [...item.local.pii_summary]
      .filter((f) => f.count > 0 && f.category !== "file_name_signal")
      .sort((x, y) => y.count - x.count)[0];
    if (!top) return piiLabel("file_name_signal");
    return piiLabel(top.category);
  }
  const first = item.remote.types[0];
  if (!first) return "-";
  return categoryLabel(first);
}

function alertRisk(item: AlertListItem): UiAlert["risk_level"] {
  if (item.kind === "local") {
    return item.local.risk_level;
  }
  const raw = item.remote.risk_level as UiAlert["risk_level"];
  return raw;
}

function alertTime(item: AlertListItem): number {
  return item.kind === "local" ? item.local.last_seen_at : item.remote.received_at;
}

function alertDeviceLabel(item: AlertListItem): string {
  return item.kind === "local" ? t("alerts.local") : item.remote.device_name;
}

function visibleAlerts(): AlertListItem[] {
  let items: AlertListItem[] = alerts
    .filter((a) => (showIgnored ? true : !a.ignored))
    .map((a) => ({ kind: "local", local: a }));
  if (isServerMode()) {
    items = items.concat(serverAlerts.map((a) => ({ kind: "server", remote: a })));
  }

  if (selectedRiskFilters.size > 0) {
    items = items.filter((a) => selectedRiskFilters.has(alertRisk(a)));
  }
  if (selectedTypeFilters.size > 0) {
    items = items.filter((a) =>
      Array.from(selectedTypeFilters).some((selectedType) => alertHasType(a, selectedType)),
    );
  }
  if (isServerMode() && selectedDeviceFilter !== "all") {
    items = items.filter((a) => {
      if (selectedDeviceFilter === "local") {
        return a.kind === "local";
      }
      return a.kind === "server" && a.remote.device_id === selectedDeviceFilter;
    });
  }

  items = [...items].sort((a, b) => {
    if (sortBy === "risk_desc") {
      return riskRank(alertRisk(b)) - riskRank(alertRisk(a)) || alertTime(b) - alertTime(a);
    }
    if (sortBy === "risk_asc") {
      return riskRank(alertRisk(a)) - riskRank(alertRisk(b)) || alertTime(b) - alertTime(a);
    }
    if (sortBy === "recent") {
      return alertTime(b) - alertTime(a);
    }
    return primaryType(a).localeCompare(primaryType(b));
  });

  return items;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatInlineMarkdown(text: string): string {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  out = out.replace(
    /\[([^\]]+)\]\((https?:\/\/[^\s)]+|mailto:[^\s)]+)\)/g,
    '<a href="$2" target="_blank" rel="noreferrer">$1</a>',
  );
  return out;
}

function markdownToHtml(markdown: string): string {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  let html = "";
  let inUl = false;
  let inOl = false;
  let inCode = false;
  let paragraph: string[] = [];

  const flushParagraph = () => {
    if (paragraph.length > 0) {
      html += `<p>${formatInlineMarkdown(paragraph.join(" "))}</p>`;
      paragraph = [];
    }
  };
  const closeLists = () => {
    if (inUl) {
      html += "</ul>";
      inUl = false;
    }
    if (inOl) {
      html += "</ol>";
      inOl = false;
    }
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      flushParagraph();
      closeLists();
      html += inCode ? "</code></pre>" : "<pre><code>";
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      html += `${escapeHtml(rawLine)}\n`;
      continue;
    }

    if (!trimmed) {
      flushParagraph();
      closeLists();
      continue;
    }

    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      closeLists();
      const level = heading[1].length;
      html += `<h${level}>${formatInlineMarkdown(heading[2])}</h${level}>`;
      continue;
    }

    const ulItem = trimmed.match(/^[-*]\s+(.+)$/);
    if (ulItem) {
      flushParagraph();
      if (inOl) {
        html += "</ol>";
        inOl = false;
      }
      if (!inUl) {
        html += "<ul>";
        inUl = true;
      }
      html += `<li>${formatInlineMarkdown(ulItem[1])}</li>`;
      continue;
    }

    const olItem = trimmed.match(/^\d+\.\s+(.+)$/);
    if (olItem) {
      flushParagraph();
      if (inUl) {
        html += "</ul>";
        inUl = false;
      }
      if (!inOl) {
        html += "<ol>";
        inOl = true;
      }
      html += `<li>${formatInlineMarkdown(olItem[1])}</li>`;
      continue;
    }

    paragraph.push(trimmed);
  }

  flushParagraph();
  closeLists();
  if (inCode) html += "</code></pre>";
  return html;
}

function renderMarkdownBlock(markdown: string, className = "markdown-content"): HTMLElement {
  const block = el("div", className);
  block.innerHTML = markdownToHtml(markdown);
  for (const anchor of block.querySelectorAll("a[href]")) {
    anchor.addEventListener("click", (event) => {
      event.preventDefault();
      const href = (anchor as HTMLAnchorElement).href;
      void openPath(href);
    });
  }
  return block;
}

async function openAgplLicense(): Promise<void> {
  await openPath("https://www.gnu.org/licenses/agpl-3.0.html");
}

async function refreshAlerts(): Promise<void> {
  debugLog("refreshAlerts:start");
  alerts = await listAlerts();
  if (isServerMode()) {
    serverAlerts = await listServerAlerts(200);
  } else {
    serverAlerts = [];
  }
  debugLog("refreshAlerts:done", { count: alerts.length });
  if (selectedFileId && !alerts.find((a) => a.file_id === selectedFileId)) {
    selectedFileId = null;
    selectedReport = null;
    showRevealed = false;
  }
  render();
}

async function refreshSettings(): Promise<void> {
  try {
    appSettings = await getSettings();
    debugLog("refreshSettings:done", appSettings);
  } catch {
    appSettings = null;
    debugLog("refreshSettings:error");
  }
  render();
}

async function refreshTypeDefinitions(): Promise<void> {
  if (typeDefinitionsLoading) return;
  typeDefinitionsLoading = true;
  typeDefinitionsError = null;
  render();
  try {
    typeDefinitions = await listTypeDefinitions();
    typeDefinitionsLoaded = true;
  } catch (error) {
    typeDefinitions = [];
    typeDefinitionsLoaded = false;
    typeDefinitionsError = error instanceof Error ? error.message : String(error);
  } finally {
    typeDefinitionsLoading = false;
  }
  render();
}

async function refreshAgentsState(): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    agentsState = await getAgentsState();
    await refreshServerPanelData();
  } catch (error) {
    agentsState = null;
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    agentsLoading = false;
    render();
  }
}

async function refreshServerPanelData(): Promise<void> {
  if (agentsState?.mode !== "server") {
    serverDevices = [];
    serverAlerts = [];
    serverHostTypesYaml = "types: []\n";
    return;
  }

  try {
    const [devices, alerts, hostYaml] = await Promise.all([
      listServerDevices(),
      listServerAlerts(50),
      getServerHostTypesYaml(),
    ]);
    serverDevices = devices;
    serverAlerts = alerts;
    serverHostTypesYaml = hostYaml;
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  }
}

async function onSetAgentsMode(mode: AgentsMode): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    agentsState = await setAgentsMode(mode);
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    await refreshServerPanelData();
    agentsLoading = false;
    render();
  }
}

async function onCreateServerCode(): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    agentsState = await createServerPairCode(30);
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    await refreshServerPanelData();
    agentsLoading = false;
    render();
  }
}

async function onPairAsAgent(confirmInternet: boolean): Promise<void> {
  const days = Number.parseInt(agentPairDaysInput, 10);
  const validDays = Number.isFinite(days) ? Math.min(180, Math.max(1, days)) : 14;

  agentsLoading = true;
  agentsError = null;
  render();
  try {
    agentsState = await pairAsAgent(
      agentServerUrlInput,
      agentPairCodeInput,
      confirmInternet,
      validDays,
    );
    await syncHostTypesFromServer();
    await refreshTypeDefinitions();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("internet_confirmation_required") && !confirmInternet) {
      const approved = window.confirm(t("agents.internetConfirm"));
      if (approved) {
        agentsLoading = false;
        render();
        await onPairAsAgent(true);
        return;
      }
      agentsError = t("agents.internetDeclined");
    } else {
      agentsError = message;
    }
  } finally {
    await refreshServerPanelData();
    agentsLoading = false;
    render();
  }
}

async function onUnpairAgent(): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    agentsState = await unpairAgent();
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    await refreshServerPanelData();
    agentsLoading = false;
    render();
  }
}

async function onToggleServerDevice(deviceId: string, enabled: boolean): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    await setServerDeviceEnabled(deviceId, enabled);
    await refreshServerPanelData();
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    agentsLoading = false;
    render();
  }
}

async function onUnpairServerDevice(deviceId: string): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    await unpairServerDevice(deviceId);
    await refreshServerPanelData();
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    agentsLoading = false;
    render();
  }
}

async function onSaveServerHostTypes(): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    await setServerHostTypesYaml(serverHostTypesYaml);
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    agentsLoading = false;
    render();
  }
}

async function onSyncHostTypes(): Promise<void> {
  agentsLoading = true;
  agentsError = null;
  render();
  try {
    await syncHostTypesFromServer();
    await refreshTypeDefinitions();
  } catch (error) {
    agentsError = error instanceof Error ? error.message : String(error);
  } finally {
    agentsLoading = false;
    render();
  }
}

async function selectFile(fileId: number): Promise<void> {
  debugLog("selectFile:start", { fileId });
  reportPanelVisible = true;
  selectedFileId = fileId;
  showRevealed = false;
  revealLoading = false;
  neutralizeLoading = false;
  onDemandScanLoading = false;
  reportDropActive = false;
  expandedRedacted.clear();
  reportLoadError = null;
  try {
    selectedReport = await getReport(fileId, false);
    debugLog("selectFile:reportLoaded", { fileId, findings: selectedReport.findings.length });
  } catch (error) {
    selectedReport = null;
    reportLoadError = error instanceof Error ? error.message : String(error);
  }
  render();
}

async function toggleReveal(): Promise<void> {
  if (!selectedFileId) return;
  if (revealLoading) return;

  revealLoading = true;
  render();

  if (!showRevealed) {
    try {
      selectedReport = await getReport(selectedFileId, true);
      debugLog("toggleReveal:revealed", { fileId: selectedFileId });
      reportLoadError = null;
      showRevealed = true;
    } catch (error) {
      reportLoadError = error instanceof Error ? error.message : String(error);
    }
  } else {
    showRevealed = false;
    try {
      selectedReport = await getReport(selectedFileId, false);
      debugLog("toggleReveal:hidden", { fileId: selectedFileId });
      reportLoadError = null;
    } catch (error) {
      reportLoadError = error instanceof Error ? error.message : String(error);
    }
  }
  revealLoading = false;
  render();
}

async function onDelete(): Promise<void> {
  if (!selectedFileId) return;
  confirmAction = { kind: "deleteFile", fileId: selectedFileId };
  render();
}

async function onNeutralize(): Promise<void> {
  if (!selectedFileId || neutralizeLoading) return;
  confirmAction = { kind: "neutralizeFile", fileId: selectedFileId };
  render();
}

async function onIgnoreToggle(): Promise<void> {
  if (!selectedFileId) return;
  const a = alerts.find((x) => x.file_id === selectedFileId);
  if (!a) return;
  if (a.ignored) {
    await unignoreFile(selectedFileId);
  } else {
    await ignoreFile(selectedFileId);
  }
  await refreshAlerts();
}

async function onConfirmAction(): Promise<void> {
  const action = confirmAction;
  if (!action) return;
  confirmAction = null;
  render();
  if (action.kind === "stopScan") {
    await stopScan();
    return;
  }
  if (action.kind === "scanRunning") {
    return;
  }
  if (action.kind === "deleteFile") {
    await deleteFileToTrash(action.fileId);
    await refreshAlerts();
    return;
  }
  if (action.kind === "neutralizeFile") {
    neutralizeLoading = true;
    render();
    try {
      await neutralizeFile(action.fileId);
      await refreshAlerts();
      if (selectedFileId === action.fileId) {
        selectedReport = await getReport(action.fileId, false);
        showRevealed = false;
        expandedRedacted.clear();
      }
    } catch (error) {
      reportLoadError = error instanceof Error ? error.message : String(error);
    } finally {
      neutralizeLoading = false;
      render();
    }
    return;
  }
  if (action.kind === "clearAll") {
    await clearAlerts();
    await refreshAlerts();
    return;
  }
}

function render(): void {
  const prevList = appEl.querySelector<HTMLDivElement>(".alert-list");
  if (prevList) {
    alertsListScrollTop = prevList.scrollTop;
  }
  const active = document.activeElement as HTMLElement | null;
  const focusedAlertId =
    active?.classList.contains("alert-item") && active.dataset.fileId
      ? active.dataset.fileId
      : null;

  const root = el("div", "app");

  const header = el("header", "top");
  const brand = el("div", "brand");
  const wordmark = document.createElement("img");
  wordmark.className = "brand-wordmark";
  wordmark.src = pdwnWordmark;
  wordmark.alt = "PDWN";
  brand.append(wordmark);
  brand.append(el("div", "brand-tagline", t("app.tagline")));
  header.append(brand);

  const controls = el("div", "controls");

  // Debug mode indicator
  if (debugMode) {
    const debugBadge = el("span", "debug-badge", "DEBUG");
    debugBadge.title = "Debug mode active (Ctrl+Shift+D to toggle)";
    controls.append(debugBadge);
  }

  const scanBtn = el("button", "btn");
  if (isScanning) {
    scanBtn.append(el("span", "spinner"));
    const p = scanProgress;
    scanBtn.title = p
      ? t("actions.scanProgress", { processed: p.processed, total: p.total || "?" })
      : t("actions.scanRunning");
  } else {
    scanBtn.append(el("span", "", "🔎"));
    scanBtn.title = t("actions.scan");
  }
  scanBtn.append(document.createTextNode(` ${t("actions.scan")}`));
  scanBtn.addEventListener("click", () => void onScanNow());
  controls.append(scanBtn);

  const menuBtn = el("button", "btn", "☰");
  menuBtn.title = t("menu.title");
  menuBtn.addEventListener("click", () => {
    menuOpen = !menuOpen;
    render();
  });
  controls.append(menuBtn);

  if (menuOpen) {
    const menu = el("div", "menu");
    const aboutBtn = el("button", "menu-item", t("menu.about"));
    aboutBtn.addEventListener("click", () => {
      dialog = "about";
      aboutTab = "about";
      legalDependenciesVisible = false;
      menuOpen = false;
      render();
    });
    menu.append(aboutBtn);
    const customBtn = el("button", "menu-item", t("menu.types"));
    customBtn.addEventListener("click", () => {
      dialog = "types";
      typesTab = "custom";
      menuOpen = false;
      if (!typeDefinitionsLoaded && !typeDefinitionsLoading) {
        void refreshTypeDefinitions();
      }
      render();
    });
    menu.append(customBtn);

    const agentsBtn = el("button", "menu-item", t("menu.agents"));
    agentsBtn.addEventListener("click", () => {
      dialog = "agents";
      menuOpen = false;
      agentsError = null;
      void refreshAgentsState();
      render();
    });
    menu.append(agentsBtn);

    const clearBtn = el("button", "menu-item", t("menu.clearAll"));
    clearBtn.addEventListener("click", async () => {
      confirmAction = { kind: "clearAll" };
      menuOpen = false;
      render();
    });
    menu.append(clearBtn);
    controls.append(menu);
  }
  header.append(controls);
  root.append(header);

  const watchBar = el("div", "watch");
  watchBar.append(el("span", "watch-label", `${t("settings.watching")}:`));
  const dirsWrap = el("div", "watch-dirs");
  const dirs = appSettings?.watched_directories ?? [];
  if (dirs.length === 0) {
    dirsWrap.append(el("span", "watch-value", t("settings.watchingUnavailable")));
  } else {
    for (const [idx, d] of dirs.entries()) {
      const chip = el("button", "watch-chip", d);
      chip.title = t("settings.editFolder");
      chip.addEventListener("click", () => void editWatchedDirectory(idx));
      dirsWrap.append(chip);

      if (dirs.length > 1) {
        const remove = el("button", "watch-remove", "−");
        remove.title = t("settings.removeFolder");
        remove.addEventListener("click", (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          void removeWatchedDirectory(idx);
        });
        dirsWrap.append(remove);
      }
    }
  }
  const addDirBtn = el("button", "btn btn-mini", withIcon("＋", t("settings.addFolder")));
  addDirBtn.addEventListener("click", () => void addWatchedDirectory());
  watchBar.append(dirsWrap);
  watchBar.append(addDirBtn);
  root.append(watchBar);

  const main = el("main", "grid");
  if (!reportPanelVisible) {
    main.classList.add("report-hidden");
  }

  const left = el("section", "panel");
  left.append(el("h2", "panel-title", t("alerts.title")));
  const filters = el("div", "filters");

  const riskWrap = el("div", "filter filter-dropdown");
  riskWrap.append(el("span", "filter-label", t("filters.risk")));
  const riskBtn = el("button", "filter-trigger", riskFilterLabel());
  riskBtn.type = "button";
  riskBtn.addEventListener("click", (ev) => {
    ev.preventDefault();
    riskFilterOpen = !riskFilterOpen;
    if (riskFilterOpen) {
      typeFilterOpen = false;
    }
    render();
  });
  riskWrap.append(riskBtn);
  if (riskFilterOpen) {
    const menu = el("div", "filter-menu");
    const allLine = el("label", "filter-option");
    const allCb = document.createElement("input");
    allCb.type = "checkbox";
    allCb.checked = selectedRiskFilters.size === 0;
    allCb.addEventListener("change", () => {
      selectedRiskFilters.clear();
      render();
    });
    allLine.append(allCb);
    allLine.append(el("span", "", t("filters.all")));
    menu.append(allLine);
    for (const level of RISK_FILTER_OPTIONS) {
      const line = el("label", "filter-option");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = selectedRiskFilters.has(level);
      cb.addEventListener("change", () => {
        toggleSelection(selectedRiskFilters, level);
        render();
      });
      line.append(cb);
      line.append(el("span", "", riskLabel(level)));
      menu.append(line);
    }
    riskWrap.append(menu);
  }
  filters.append(riskWrap);

  const typeWrap = el("div", "filter filter-dropdown");
  typeWrap.append(el("span", "filter-label", t("filters.type")));
  const typeBtn = el("button", "filter-trigger", typeFilterLabel());
  typeBtn.type = "button";
  typeBtn.addEventListener("click", (ev) => {
    ev.preventDefault();
    typeFilterOpen = !typeFilterOpen;
    if (typeFilterOpen) {
      riskFilterOpen = false;
    }
    render();
  });
  typeWrap.append(typeBtn);

  const typeOptions: string[] = [...BUILTIN_TYPE_FILTER_OPTIONS];
  const customTypeOptions = Array.from(
    new Set(
      alerts
        .flatMap((a) => a.custom_summary.map((c) => c.category))
        .filter((c) => c && c.trim().length > 0),
    ),
  ).sort((a, b) => a.localeCompare(b));
  if (isServerMode()) {
    for (const alert of serverAlerts) {
      for (const type of alert.types) {
        if (!isBuiltinCategory(type) && !customTypeOptions.includes(type)) {
          customTypeOptions.push(type);
        }
      }
    }
    customTypeOptions.sort((a, b) => a.localeCompare(b));
  }
  typeOptions.push(...customTypeOptions);
  if (typeFilterOpen) {
    const menu = el("div", "filter-menu");
    const allLine = el("label", "filter-option");
    const allCb = document.createElement("input");
    allCb.type = "checkbox";
    allCb.checked = selectedTypeFilters.size === 0;
    allCb.addEventListener("change", () => {
      selectedTypeFilters.clear();
      render();
    });
    allLine.append(allCb);
    allLine.append(el("span", "", t("filters.all")));
    menu.append(allLine);
    for (const v of typeOptions) {
      const line = el("label", "filter-option");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = selectedTypeFilters.has(v);
      cb.addEventListener("change", () => {
        toggleSelection(selectedTypeFilters, v);
        render();
      });
      line.append(cb);
      const label =
        v !== "all" && !isBuiltinCategory(v) ? `${categoryLabel(v)} *` : categoryLabel(v);
      line.append(el("span", "", label));
      menu.append(line);
    }
    typeWrap.append(menu);
  }
  filters.append(typeWrap);

  const sortWrap = el("label", "filter");
  sortWrap.append(el("span", "filter-label", t("filters.sort")));
  const sortSelect = document.createElement("select");
  const sorts: Array<{ value: SortMode; label: string }> = [
    { value: "risk_desc", label: t("filters.sortRiskDesc") },
    { value: "risk_asc", label: t("filters.sortRiskAsc") },
    { value: "recent", label: t("filters.sortRecent") },
    { value: "type", label: t("filters.sortType") },
  ];
  for (const v of sorts) {
    const opt = document.createElement("option");
    opt.value = v.value;
    opt.textContent = v.label;
    if (v.value === sortBy) opt.selected = true;
    sortSelect.append(opt);
  }
  sortSelect.addEventListener("change", () => {
    sortBy = sortSelect.value as SortMode;
    render();
  });
  sortWrap.append(sortSelect);
  filters.append(sortWrap);

  const ignoredWrap = el("label", "filter-inline");
  const ignoredCb = document.createElement("input");
  ignoredCb.type = "checkbox";
  ignoredCb.checked = showIgnored;
  ignoredCb.addEventListener("change", () => {
    showIgnored = ignoredCb.checked;
    render();
  });
  ignoredWrap.append(ignoredCb);
  ignoredWrap.append(el("span", "filter-label", t("filters.showIgnored")));
  filters.append(ignoredWrap);

  if (isServerMode()) {
    const deviceWrap = el("label", "filter");
    deviceWrap.append(el("span", "filter-label", t("filters.device")));
    const deviceSelect = document.createElement("select");
    const allOpt = document.createElement("option");
    allOpt.value = "all";
    allOpt.textContent = t("filters.all");
    allOpt.selected = selectedDeviceFilter === "all";
    deviceSelect.append(allOpt);

    const localOpt = document.createElement("option");
    localOpt.value = "local";
    localOpt.textContent = t("alerts.local");
    localOpt.selected = selectedDeviceFilter === "local";
    deviceSelect.append(localOpt);

    const devices = new Map<string, string>();
    for (const a of serverAlerts) {
      devices.set(a.device_id, a.device_name);
    }
    const sorted = Array.from(devices.entries()).sort((a, b) => a[1].localeCompare(b[1]));
    for (const [id, name] of sorted) {
      const opt = document.createElement("option");
      opt.value = id;
      opt.textContent = name;
      opt.selected = selectedDeviceFilter === id;
      deviceSelect.append(opt);
    }

    deviceSelect.addEventListener("change", () => {
      selectedDeviceFilter = deviceSelect.value;
      render();
    });
    deviceWrap.append(deviceSelect);
    filters.append(deviceWrap);
  } else {
    selectedDeviceFilter = "all";
  }

  left.append(filters);

  const list = el("div", "alert-list");
  const visible = visibleAlerts();
  if (visible.length === 0) {
    list.append(el("div", "empty", t("alerts.empty")));
  } else {
    for (const itemData of visible) {
      const isLocal = itemData.kind === "local";
      const fileId = isLocal ? itemData.local.file_id : null;
      const path = isLocal ? itemData.local.path : itemData.remote.path;
      const riskLevel = isLocal ? itemData.local.risk_level : alertRisk(itemData);
      const ignored = isLocal ? itemData.local.ignored : false;
      const item = el("button", "alert-item");
      if (fileId !== null) {
        item.dataset.fileId = String(fileId);
      }
      if (fileId !== null && fileId === selectedFileId) item.dataset.selected = "true";
      if (ignored) item.dataset.ignored = "true";
      if (!isLocal) {
        (item as HTMLButtonElement).disabled = true;
      }

      const topRow = el("div", "alert-top");
      const nameEl = el("div", "alert-path", fileNameFromPath(path));
      nameEl.title = path;
      topRow.append(nameEl);

      const badge = el("div", `badge badge-${riskLevel}`, riskLabel(riskLevel));
      topRow.append(badge);
      item.append(topRow);

      const meta = el("div", "alert-meta");
      if (isLocal) {
        meta.append(
          el("div", "alert-types", summarizeTypes(itemData.local) || piiLabel("file_name_signal")),
        );
      } else {
        meta.append(el("div", "alert-types", itemData.remote.types.join(", ") || "-"));
      }
      meta.append(el("div", "alert-age", fmtAge(alertTime(itemData))));
      if (!isLocal && isServerMode()) {
        meta.append(el("div", "alert-age", `${t("alerts.device")}: ${alertDeviceLabel(itemData)}`));
      }
      item.append(meta);

      if (fileId !== null) {
        item.addEventListener("click", () => void selectFile(fileId));
      }
      list.append(item);
    }
  }
  left.append(list);
  main.append(left);

  if (reportPanelVisible) {
    const right = el("section", "panel");
    const reportHeader = el("div", "panel-title panel-title-row");
    reportHeader.append(el("span", "", t("report.title")));
    const closeReportBtn = el("button", "btn btn-mini", withIcon("✕", t("common.close")));
    closeReportBtn.addEventListener("click", () => {
      reportPanelVisible = false;
      selectedReport = null;
      showRevealed = false;
      neutralizeLoading = false;
      onDemandScanLoading = false;
      reportDropActive = false;
      reportLoadError = null;
      expandedRedacted.clear();
      render();
    });
    reportHeader.append(closeReportBtn);
    right.append(reportHeader);
    const body = el("div", "report");
    if (reportLoadError) {
      body.append(el("div", "warn", t("report.loadError", { error: reportLoadError })));
      if (!selectedReport) {
        body.append(renderOnDemandDropzone());
      }
    } else if (!selectedReport) {
      body.append(renderOnDemandDropzone());
    } else {
      const r = selectedReport;
      const persistedReport = selectedFileId !== null;
      const meta = el("div", "report-meta");
      const metaLeft = el("div", "report-meta-left");
      metaLeft.append(kvRow(t("report.fileName"), fileNameFromPath(r.path), "kv-row-file"));
      metaLeft.append(kvRow(t("report.path"), r.path, "kv-row-path"));
      const metaRight = el("div", "report-meta-right");
      metaRight.append(kvRow(t("alerts.risk"), `${riskLabel(r.risk_level)} (${r.risk_score})`));
      metaRight.append(kvRow(t("report.size"), fmtBytes(r.size)));
      metaRight.append(kvRow(t("report.modified"), fmtDate(r.mtime)));
      meta.append(metaLeft, metaRight);
      body.append(meta);

      if (r.weak_zip_encryption) {
        const warn = el("div", "warn");
        warn.append(el("div", "warn-title", t("report.weakEncryption")));
        warn.append(el("div", "warn-body", t("report.weakEncryptionDesc")));
        body.append(warn);
      }

      body.append(el("h3", "sub", t("report.findings")));
      body.append(renderFindings(r));

      const reasonItems: string[] = [];
      for (const reason of r.reasons.slice(0, 12)) {
        const vars = { ...(reason.vars ?? {}) } as Record<string, unknown>;
        if (typeof vars.category === "string") {
          vars.category = piiLabel(vars.category);
        }
        if (typeof vars.risk === "string") {
          vars.risk = riskLabel(vars.risk as UiAlert["risk_level"]);
        }
        const text = t(reason.key, vars as never).trim();
        if (text.length > 0) {
          reasonItems.push(text);
        }
      }
      if (reasonItems.length > 0) {
        body.append(el("h3", "sub", t("report.reasons")));
        const reasons = el("ul", "reasons");
        for (const text of reasonItems) {
          const li = document.createElement("li");
          li.textContent = text;
          reasons.append(li);
        }
        body.append(reasons);
      }

      const actions = el("div", "actions");
      const openFolderBtn = el("button", "btn", withIcon("📂", t("actions.openFolder")));
      openFolderBtn.addEventListener("click", async () => {
        debugLog("openFolder:click", { path: r.path });
        const idx = Math.max(r.path.lastIndexOf("/"), r.path.lastIndexOf("\\"));
        const folder = idx > 0 ? r.path.slice(0, idx) : r.path;
        try {
          await openInFileManager(r.path);
          debugLog("openFolder:backendOk", { file: r.path });
        } catch (backendError) {
          console.warn("open folder backend failed", backendError);
          try {
            await revealItemInDir(r.path);
            debugLog("openFolder:revealed", { file: r.path });
          } catch (error) {
            console.warn("open folder reveal failed, fallback openPath", error);
            try {
              await openPath(folder);
              debugLog("openFolder:fallbackFolder", { folder });
            } catch (folderError) {
              console.warn("open folder fallback failed, opening file", folderError);
              await openPath(r.path);
              debugLog("openFolder:fallbackFile", { file: r.path });
            }
          }
        }
      });
      actions.append(openFolderBtn);

      const ignoreBtn = el(
        "button",
        "btn",
        alerts.find((a) => a.file_id === r.file_id)?.ignored
          ? withIcon("✅", t("actions.unignore"))
          : withIcon("🚫", t("actions.ignore")),
      );
      (ignoreBtn as HTMLButtonElement).disabled = !persistedReport;
      ignoreBtn.addEventListener("click", () => void onIgnoreToggle());
      actions.append(ignoreBtn);

      const revealAllowed = canRevealReport(r);
      const hasAnyFinding =
        r.findings.some((f) => f.count > 0) || r.custom_findings.some((f) => f.count > 0);
      const revealBtn = el(
        "button",
        "btn",
        revealLoading
          ? t(showRevealed ? "actions.hide" : "actions.reveal")
          : withIcon(
              showRevealed ? "🙈" : "👁",
              t(showRevealed ? "actions.hide" : "actions.reveal"),
            ),
      );
      if (revealLoading) {
        revealBtn.prepend(el("span", "spinner"));
      }
      (revealBtn as HTMLButtonElement).disabled =
        !persistedReport || !revealAllowed || revealLoading;
      revealBtn.addEventListener("click", () => void toggleReveal());
      actions.append(revealBtn);
      if (!revealAllowed && hasAnyFinding) {
        body.append(el("div", "empty", t("report.revealUnavailable")));
      }

      const neutralizeBtn = el(
        "button",
        "btn danger",
        neutralizeLoading ? t("actions.neutralize") : withIcon("🧼", t("actions.neutralize")),
      );
      const neutralizeAllowed = canNeutralizeReport(r);
      if (neutralizeLoading) {
        neutralizeBtn.prepend(el("span", "spinner"));
      }
      (neutralizeBtn as HTMLButtonElement).disabled =
        !persistedReport || neutralizeLoading || !neutralizeAllowed;
      neutralizeBtn.addEventListener("click", () => void onNeutralize());
      actions.append(neutralizeBtn);

      const deleteBtn = el("button", "btn danger", withIcon("🗑", t("actions.delete")));
      (deleteBtn as HTMLButtonElement).disabled = !persistedReport;
      deleteBtn.addEventListener("click", () => void onDelete());
      actions.append(deleteBtn);

      body.append(actions);
      if (!persistedReport) {
        body.append(el("div", "empty", t("report.onDemandActionsUnavailable")));
      }
    }
    right.append(body);
    main.append(right);
  }

  root.append(main);

  if (dialog) {
    const overlay = el("div", "overlay");
    const card = el("div", "dialog");
    const head = el("div", "dialog-head");
    const dialogTitle =
      dialog === "types"
        ? t("menu.types")
        : dialog === "agents"
          ? t("menu.agents")
          : t("menu.about");
    head.append(el("h3", "dialog-title", dialogTitle));
    const close = el("button", "btn btn-mini", withIcon("✕", t("common.close")));
    close.addEventListener("click", () => {
      dialog = null;
      render();
    });
    head.append(close);
    card.append(head);

    const body = el("div", "dialog-body");
    if (dialog === "about") {
      const tabs = el("div", "dialog-tabs");
      const tAbout = el(
        "button",
        `btn btn-mini ${aboutTab === "about" ? "active-tab" : ""}`,
        t("menu.about"),
      );
      tAbout.addEventListener("click", () => {
        aboutTab = "about";
        legalDependenciesVisible = false;
        render();
      });
      tabs.append(tAbout);
      const tLegal = el(
        "button",
        `btn btn-mini ${aboutTab === "legal" ? "active-tab" : ""}`,
        t("menu.legal"),
      );
      tLegal.addEventListener("click", () => {
        aboutTab = "legal";
        render();
      });
      tabs.append(tLegal);
      body.append(tabs);
      if (aboutTab === "about") {
        body.append(renderMarkdownBlock(aboutMarkdown));
      } else {
        const actions = el("div", "legal-actions");
        const agplBtn = el("button", "btn btn-mini", withIcon("↗", t("about.openAgplLink")));
        agplBtn.addEventListener("click", () => void openAgplLicense());
        actions.append(agplBtn);

        const depsBtn = el(
          "button",
          "btn btn-mini",
          withIcon(
            "📦",
            t(legalDependenciesVisible ? "about.hideDependencies" : "about.showDependencies"),
          ),
        );
        depsBtn.addEventListener("click", () => {
          legalDependenciesVisible = !legalDependenciesVisible;
          render();
        });
        actions.append(depsBtn);
        body.append(renderMarkdownBlock(legalMarkdown));

        if (legalDependenciesVisible) {
          body.append(el("h4", "entity-section-title", t("about.dependenciesTitle")));
          body.append(
            renderMarkdownBlock(dependenciesMarkdown, "markdown-content dependencies-content"),
          );
        }
        body.append(actions);
      }
    } else if (dialog === "agents") {
      const modeTabs = el("div", "dialog-tabs");
      const modeAgent = el(
        "button",
        `btn btn-mini ${agentsState?.mode !== "server" ? "active-tab" : ""}`,
        t("agents.modeAgent"),
      );
      modeAgent.addEventListener("click", () => void onSetAgentsMode("agent"));
      modeTabs.append(modeAgent);
      const modeServer = el(
        "button",
        `btn btn-mini ${agentsState?.mode === "server" ? "active-tab" : ""}`,
        t("agents.modeServer"),
      );
      modeServer.addEventListener("click", () => void onSetAgentsMode("server"));
      modeTabs.append(modeServer);
      body.append(modeTabs);

      if (agentsLoading) {
        body.append(el("div", "empty", t("agents.loading")));
      }
      if (agentsError) {
        body.append(el("div", "warn", agentsError));
      }

      if (agentsState?.mode === "server") {
        body.append(el("div", "suggestion", t("agents.serverHelp")));
        body.append(
          kvRow(t("agents.serverAddress"), agentsState.server_listen_addr ?? t("agents.loading")),
        );
        const code = agentsState.server_pair_code;
        const expires = agentsState.server_pair_code_expires_at;
        const codeValue = code ?? "-";
        body.append(kvRow(t("agents.serverCode"), codeValue));
        body.append(
          kvRow(
            t("agents.serverCodeExpires"),
            expires ? fmtDate(expires) : t("agents.serverCodeMissing"),
          ),
        );
        const actions = el("div", "actions");
        const genBtn = el(
          "button",
          "btn",
          code ? t("agents.regenerateCode") : t("agents.generateCode"),
        );
        genBtn.addEventListener("click", () => void onCreateServerCode());
        actions.append(genBtn);
        const copyBtn = el("button", "btn", t("agents.copyCode"));
        (copyBtn as HTMLButtonElement).disabled = !code;
        copyBtn.addEventListener("click", async () => {
          if (!code) return;
          await navigator.clipboard.writeText(code);
        });
        actions.append(copyBtn);
        body.append(actions);

        body.append(el("h4", "entity-section-title", t("agents.devicesTitle")));
        if (serverDevices.length === 0) {
          body.append(el("div", "empty", t("agents.devicesEmpty")));
        } else {
          const devicesList = el("div", "type-list");
          for (const device of serverDevices) {
            const card = el("div", "report-meta");
            const leftCol = el("div", "report-meta-left");
            leftCol.append(kvRow(t("agents.deviceName"), device.device_name));
            leftCol.append(kvRow(t("agents.deviceId"), device.device_id));
            leftCol.append(kvRow(t("agents.devicePairedAt"), fmtDate(device.paired_at)));
            leftCol.append(kvRow(t("agents.deviceExpiresAt"), fmtDate(device.expires_at)));
            const rightCol = el("div", "report-meta-right");
            rightCol.append(
              kvRow(
                t("agents.deviceLastSeen"),
                device.last_seen_at ? fmtDate(device.last_seen_at) : t("agents.deviceNever"),
              ),
            );
            rightCol.append(
              kvRow(
                t("agents.deviceStatus"),
                device.enabled ? t("agents.deviceEnabled") : t("agents.deviceDisabled"),
              ),
            );
            const rowActions = el("div", "actions");
            const toggleBtn = el(
              "button",
              "btn btn-mini",
              device.enabled ? t("agents.disableDevice") : t("agents.enableDevice"),
            );
            toggleBtn.addEventListener(
              "click",
              () => void onToggleServerDevice(device.device_id, !device.enabled),
            );
            rowActions.append(toggleBtn);
            const unpairBtn = el("button", "btn btn-mini danger", t("agents.unpairDevice"));
            unpairBtn.addEventListener("click", () => void onUnpairServerDevice(device.device_id));
            rowActions.append(unpairBtn);
            rightCol.append(rowActions);
            card.append(leftCol, rightCol);
            devicesList.append(card);
          }
          body.append(devicesList);
        }

        body.append(el("h4", "entity-section-title", t("agents.hostTypesTitle")));
        const hostTypesInput = document.createElement("textarea");
        hostTypesInput.className = "custom-input";
        hostTypesInput.rows = 8;
        hostTypesInput.value = serverHostTypesYaml;
        hostTypesInput.addEventListener("input", () => {
          serverHostTypesYaml = hostTypesInput.value;
        });
        body.append(hostTypesInput);
        const hostActions = el("div", "actions");
        const saveHostBtn = el("button", "btn", t("agents.saveHostTypes"));
        saveHostBtn.addEventListener("click", () => void onSaveServerHostTypes());
        hostActions.append(saveHostBtn);
        body.append(hostActions);
      } else {
        body.append(el("div", "suggestion", t("agents.agentHelp")));
        const isPaired = isAgentPaired();
        if (isPaired) {
          body.append(kvRow(t("agents.pairedServer"), agentsState?.paired_server_url ?? "-"));
          if (!agentsState?.agent_enabled) {
            body.append(el("div", "warn", t("agents.agentDisabled")));
          }
          body.append(
            kvRow(
              t("agents.pairExpiresAt"),
              agentsState?.pair_expires_at ? fmtDate(agentsState.pair_expires_at) : "-",
            ),
          );
          const actions = el("div", "actions");
          const unpairBtn = el("button", "btn danger", t("agents.unpair"));
          unpairBtn.addEventListener("click", () => void onUnpairAgent());
          actions.append(unpairBtn);
          const syncHostBtn = el("button", "btn", t("agents.syncHostTypes"));
          syncHostBtn.addEventListener("click", () => void onSyncHostTypes());
          actions.append(syncHostBtn);
          body.append(actions);
        } else {
          if (agentsState?.pair_expired) {
            body.append(el("div", "warn", t("agents.pairExpired")));
          }

          body.append(el("label", "custom-label", t("agents.serverUrl")));
          const serverUrlInput = document.createElement("input");
          serverUrlInput.className = "custom-input";
          serverUrlInput.value = agentServerUrlInput;
          serverUrlInput.placeholder = "https://server.example.com";
          serverUrlInput.addEventListener("input", () => {
            agentServerUrlInput = serverUrlInput.value;
          });
          body.append(serverUrlInput);

          body.append(el("label", "custom-label", t("agents.pairCode")));
          const pairCodeInput = document.createElement("input");
          pairCodeInput.className = "custom-input";
          pairCodeInput.value = agentPairCodeInput;
          pairCodeInput.placeholder = "ABCD-1234";
          pairCodeInput.addEventListener("input", () => {
            agentPairCodeInput = pairCodeInput.value;
          });
          body.append(pairCodeInput);

          body.append(el("label", "custom-label", t("agents.pairDays")));
          const pairDaysInput = document.createElement("input");
          pairDaysInput.className = "custom-input";
          pairDaysInput.type = "number";
          pairDaysInput.min = "1";
          pairDaysInput.max = "180";
          pairDaysInput.value = agentPairDaysInput;
          pairDaysInput.addEventListener("input", () => {
            agentPairDaysInput = pairDaysInput.value;
          });
          body.append(pairDaysInput);

          const actions = el("div", "actions");
          const pairBtn = el("button", "btn", t("agents.pairNow"));
          pairBtn.addEventListener("click", () => void onPairAsAgent(false));
          actions.append(pairBtn);
          body.append(actions);
        }
      }
    } else if (dialog === "types") {
      const tabs = el("div", "dialog-tabs");
      const tCustom = el(
        "button",
        `btn btn-mini ${typesTab === "custom" ? "active-tab" : ""}`,
        t("types.customTab"),
      );
      tCustom.addEventListener("click", () => {
        typesTab = "custom";
        render();
      });
      tabs.append(tCustom);

      const tRegional = el(
        "button",
        `btn btn-mini ${typesTab === "regional" ? "active-tab" : ""}`,
        t("types.regionalTab"),
      );
      tRegional.addEventListener("click", () => {
        typesTab = "regional";
        render();
      });
      tabs.append(tRegional);

      const tStandard = el(
        "button",
        `btn btn-mini ${typesTab === "standard" ? "active-tab" : ""}`,
        t("types.standardTab"),
      );
      tStandard.addEventListener("click", () => {
        typesTab = "standard";
        render();
      });
      tabs.append(tStandard);

      const showHostTab = isAgentPaired();
      if (showHostTab) {
        const tHost = el(
          "button",
          `btn btn-mini ${typesTab === "host" ? "active-tab" : ""}`,
          t("types.hostTab"),
        );
        tHost.addEventListener("click", () => {
          typesTab = "host";
          render();
        });
        tabs.append(tHost);
      } else if (typesTab === "host") {
        typesTab = "custom";
      }

      const typesToolbar = el("div", "types-toolbar");
      typesToolbar.append(tabs);
      const typesActions = el("div", "types-actions");
      if (typesTab === "regional") {
        const localeBadge = el(
          "span",
          "locale-badge types-locale-badge",
          t("types.activeLocale", { locale: currentRuntimeLocale() }),
        );
        typesActions.append(localeBadge);
      }
      const reloadBtn = el("button", "btn btn-mini", withIcon("⟳", t("types.reloadBtn")));
      reloadBtn.addEventListener("click", () => void onReloadTypes());
      typesActions.append(reloadBtn);
      if (typesTab === "custom") {
        const addTypeBtn = el("button", "btn btn-mini", withIcon("＋", t("custom.add")));
        addTypeBtn.addEventListener("click", () => openCreateTypeModal());
        typesActions.append(addTypeBtn);
      }
      typesToolbar.append(typesActions);
      body.append(typesToolbar);

      if (!typeDefinitionsLoaded && !typeDefinitionsLoading && !typeDefinitionsError) {
        void refreshTypeDefinitions();
      }

      if (typeDefinitionsLoading) {
        body.append(el("div", "empty", t("types.loading")));
      } else if (typeDefinitionsError) {
        body.append(el("div", "warn", t("types.reloadError", { error: typeDefinitionsError })));
      } else {
        const scopedTypes = typesForTab(typesTab);
        const titleKeyByTab: Record<typeof typesTab, string> = {
          standard: "types.standardTypesTitle",
          regional: "types.regionalTypesTitle",
          host: "types.hostTypesTitle",
          custom: "types.customTab",
        };
        const emptyKeyByTab: Record<typeof typesTab, string> = {
          standard: "types.empty",
          regional: "types.empty",
          host: "types.empty",
          custom: "custom.empty",
        };

        const sectionHead = el("div", "types-section-head");
        sectionHead.append(el("h4", "entity-section-title", t(titleKeyByTab[typesTab])));
        if (typesTab === "standard" || typesTab === "host") {
          sectionHead.append(el("span", "readonly-badge", t("types.readOnly")));
        }
        body.append(sectionHead);

        if (scopedTypes.length === 0) {
          body.append(el("div", "empty", t(emptyKeyByTab[typesTab])));
        } else {
          const typeList = el("div", "type-list");
          const sortedTypes = [...scopedTypes].sort((a, b) => {
            const nameA = typeDisplayName(a);
            const nameB = typeDisplayName(b);
            return nameA.localeCompare(nameB);
          });

          for (const def of sortedTypes) {
            const row = el("button", "type-row") as HTMLButtonElement;
            row.type = "button";
            const name = el("div", "type-row-name", typeDisplayName(def));
            const summary = el(
              "div",
              "type-row-summary",
              `${typeCategoryLabel(def.category)} • ${riskLabel(def.risk_level as UiAlert["risk_level"])} • ${typeOriginLabel(def.origin)}`,
            );
            row.append(name);
            row.append(summary);
            row.addEventListener("click", () => openViewTypeModal(def));
            typeList.append(row);
          }
          body.append(typeList);
        }
      }
    }
    card.append(body);
    overlay.append(card);
    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) {
        dialog = null;
        render();
      }
    });
    root.append(overlay);
  }

  if (confirmAction) {
    const overlay = el("div", "overlay");
    const card = el("div", "dialog");
    const head = el("div", "dialog-head");
    head.append(el("h3", "dialog-title", t("confirmations.title")));
    card.append(head);
    const body = el("div", "dialog-body");
    let message = "";
    if (confirmAction.kind === "stopScan") {
      message = t("actions.stopScanConfirm");
    } else if (confirmAction.kind === "scanRunning") {
      message = t("actions.scanRunningChoices");
    } else if (confirmAction.kind === "deleteFile") {
      message = t("confirmations.deleteBody");
    } else if (confirmAction.kind === "neutralizeFile") {
      message = t("confirmations.neutralizeBody");
    } else {
      message = t("confirmations.clearBody");
    }
    body.append(el("p", "", message));
    const actions = el("div", "actions type-form-actions");
    if (confirmAction.kind === "scanRunning") {
      const stop = el("button", "btn danger", t("actions.stopScan"));
      stop.addEventListener("click", async () => {
        await stopScan();
        confirmAction = null;
        render();
      });
      actions.append(stop);

      const clear = el("button", "btn", t("actions.cleanAlerts"));
      clear.addEventListener("click", async () => {
        await clearAlerts();
        await refreshAlerts();
        confirmAction = null;
        render();
      });
      actions.append(clear);
    } else {
      const ok = el("button", "btn danger", t("common.confirm"));
      ok.addEventListener("click", () => void onConfirmAction());
      actions.append(ok);
    }
    const cancel = el("button", "btn", t("common.cancel"));
    cancel.addEventListener("click", () => {
      confirmAction = null;
      render();
    });
    actions.append(cancel);
    body.append(actions);
    card.append(body);
    overlay.append(card);
    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) {
        confirmAction = null;
        render();
      }
    });
    root.append(overlay);
  }

  if (typeModal) {
    const overlay = el("div", "overlay");
    const card = el("div", "dialog type-detail-dialog");
    const head = el("div", "dialog-head");
    head.append(
      el(
        "h3",
        "dialog-title",
        typeModal.mode === "create"
          ? t("custom.add")
          : typeModal.mode === "edit"
            ? `${t("custom.edit")}: ${typeDisplayName(typeModal.draft)}`
            : typeDisplayName(typeModal.draft),
      ),
    );
    const closeBtn = el("button", "btn btn-mini", t("common.close"));
    closeBtn.addEventListener("click", () => closeTypeModal());
    head.append(closeBtn);
    card.append(head);

    const body = el("div", "dialog-body");
    const form = el("div", "type-form");
    const editable = typeModal.mode !== "view";

    const labelWithTip = (labelText: string, tip: string): HTMLElement => {
      const label = el("label", "custom-label");
      label.append(el("span", "", labelText));
      const tipEl = el("span", "field-tip", "?");
      tipEl.setAttribute("title", tip);
      tipEl.setAttribute("data-tip", tip);
      tipEl.setAttribute("tabindex", "0");
      tipEl.setAttribute("aria-label", tip);
      label.append(tipEl);
      return label;
    };

    const addField = (
      labelText: string,
      value: string,
      onInput: (next: string) => void,
      tipText: string,
      placeholder = "",
    ) => {
      form.append(labelWithTip(labelText, tipText));
      const input = document.createElement("input");
      input.className = "custom-input";
      input.value = value;
      input.placeholder = placeholder;
      input.disabled = !editable;
      if (editable) {
        input.addEventListener("input", () => onInput(input.value));
      }
      form.append(input);
    };

    addField(
      "Name",
      typeModal.draft.display_name_key,
      (next) => {
        if (!typeModal) return;
        typeModal.draft.display_name_key = next;
      },
      "Name shown in the list and in scan results. Example: Patient Record Number",
      "Patient Record Number",
    );

    addField(
      "Description",
      typeModal.draft.description_key,
      (next) => {
        if (!typeModal) return;
        typeModal.draft.description_key = next;
      },
      "Explain what this type means to users.",
      "Contains hospital patient identifiers",
    );

    form.append(labelWithTip("Category", "Main data family used for classification."));
    const categorySelect = document.createElement("select");
    categorySelect.className = "custom-input";
    categorySelect.disabled = !editable;
    for (const category of ["pii", "security", "sensitive"]) {
      const opt = document.createElement("option");
      opt.value = category;
      opt.textContent = typeCategoryLabel(category);
      if ((typeModal.draft.category || "pii").toLowerCase() === category) opt.selected = true;
      categorySelect.append(opt);
    }
    if (editable) {
      categorySelect.addEventListener("change", () => {
        if (!typeModal) return;
        typeModal.draft.category = categorySelect.value;
      });
    }
    form.append(categorySelect);

    form.append(el("label", "custom-label", t("custom.riskPrompt")));
    const riskSelect = document.createElement("select");
    riskSelect.className = "custom-input";
    riskSelect.disabled = !editable;
    for (const level of ["low", "medium", "high", "critical"]) {
      const opt = document.createElement("option");
      opt.value = level;
      opt.textContent = riskLabel(level as UiAlert["risk_level"]);
      if (typeModal.draft.risk_level === level) opt.selected = true;
      riskSelect.append(opt);
    }
    if (editable) {
      riskSelect.addEventListener("change", () => {
        if (!typeModal) return;
        typeModal.draft.risk_level = riskSelect.value as UiAlert["risk_level"];
      });
    }
    form.append(riskSelect);

    addField(
      "Country",
      typeModal.draft.locale_requirement ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.locale_requirement = next.trim().toUpperCase() || null;
      },
      "Optional country restriction (ISO code). Leave empty for all countries.",
      "FR",
    );

    addField(
      "Field names to match",
      typeModal.draft.key_labels.join(", "),
      (next) => {
        if (!typeModal) return;
        typeModal.draft.key_labels = parseCsv(next);
      },
      "Comma-separated keys that indicate this data in JSON/CSV headers.",
      "patient_id, health_number",
    );

    addField(
      "Filename regex",
      typeModal.draft.filename_regex ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.filename_regex = next.trim() ? next : null;
      },
      "Regex checked against file names.",
      "(?i)\\b(patient|medical)\\b",
    );

    addField(
      "Field-name regex",
      typeModal.draft.field_name_regex ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.field_name_regex = next.trim() ? next : null;
      },
      "Regex checked against structured field names.",
      "(?i)\\bhealth_id|patient_number\\b",
    );

    addField(
      "Value regex",
      typeModal.draft.value_regex ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.value_regex = next.trim() ? next : null;
      },
      "Regex checked against extracted values.",
      "\\b\\d{13}\\b",
    );

    const advanced = document.createElement("details");
    advanced.className = "type-advanced-menu";
    const advancedSummary = document.createElement("summary");
    advancedSummary.textContent = "Advanced";
    advanced.append(advancedSummary);
    const advancedForm = el("div", "type-advanced-fields");

    const addAdvancedField = (
      labelText: string,
      value: string,
      onInput: (next: string) => void,
      tipText: string,
      placeholder = "",
    ) => {
      advancedForm.append(labelWithTip(labelText, tipText));
      const input = document.createElement("input");
      input.className = "custom-input";
      input.value = value;
      input.placeholder = placeholder;
      input.disabled = !editable;
      if (editable) {
        input.addEventListener("input", () => onInput(input.value));
      }
      advancedForm.append(input);
    };

    addAdvancedField(
      "Blocked extensions",
      typeModal.draft.advanced.blocked_extensions.join(", "),
      (next) => {
        if (!typeModal) return;
        typeModal.draft.advanced.blocked_extensions = parseCsv(next);
      },
      "Ignore these file extensions for this type.",
      "txt, log",
    );

    addAdvancedField(
      "Filename keywords",
      typeModal.draft.advanced.filename_keywords
        .map((kw) => `${kw.keyword}:${kw.score}`)
        .join(", "),
      (next) => {
        if (!typeModal) return;
        typeModal.draft.advanced.filename_keywords = parseFilenameKeywords(next);
      },
      "Boost score by filename keyword using keyword:score.",
      "patient:5, hospital:6",
    );

    addAdvancedField(
      "Positive indicators",
      typeModal.draft.positive_indicators ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.positive_indicators = next.trim() ? next : null;
      },
      "Context words that increase confidence.",
      "medical, diagnosis",
    );

    addAdvancedField(
      "Negative indicators",
      typeModal.draft.negative_indicators ?? "",
      (next) => {
        if (!typeModal) return;
        typeModal.draft.negative_indicators = next.trim() ? next : null;
      },
      "Context words that decrease confidence.",
      "template, demo",
    );

    advancedForm.append(labelWithTip("Threshold", "Confidence threshold between 0 and 1."));
    const thresholdInput = document.createElement("input");
    thresholdInput.className = "custom-input";
    thresholdInput.type = "number";
    thresholdInput.min = "0";
    thresholdInput.max = "1";
    thresholdInput.step = "0.05";
    thresholdInput.value =
      typeModal.draft.threshold === null ? "" : String(typeModal.draft.threshold);
    thresholdInput.placeholder = "0.75";
    thresholdInput.disabled = !editable;
    if (editable) {
      thresholdInput.addEventListener("input", () => {
        if (!typeModal) return;
        const n = Number.parseFloat(thresholdInput.value);
        typeModal.draft.threshold = Number.isFinite(n) ? n : null;
      });
    }
    advancedForm.append(thresholdInput);

    advanced.append(advancedForm);
    form.append(advanced);

    if (typeModal.mode === "view") {
      form.append(el("div", "field-help", typeDescription(typeModal.draft)));
    }

    if (typeModal.error) {
      form.append(el("div", "warn", typeModal.error));
    }

    const actions = el("div", "actions");
    if (editable) {
      const saveBtn = el("button", "btn", t("common.confirm"));
      saveBtn.addEventListener("click", () => void onSaveCustomType());
      saveBtn.toggleAttribute("disabled", typeModal.saving);
      actions.append(saveBtn);
    }
    const close = el("button", "btn", t("common.close"));
    close.addEventListener("click", () => closeTypeModal());
    actions.append(close);
    form.append(actions);

    body.append(form);
    card.append(body);
    overlay.append(card);
    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) {
        closeTypeModal();
      }
    });
    root.append(overlay);
  }

  appEl.replaceChildren(root);

  const nextList = appEl.querySelector<HTMLDivElement>(".alert-list");
  if (nextList) {
    nextList.scrollTop = alertsListScrollTop;
  }

  if (focusedAlertId) {
    const nextFocused = appEl.querySelector<HTMLButtonElement>(
      `.alert-item[data-file-id="${focusedAlertId}"]`,
    );
    nextFocused?.focus({ preventScroll: true });
  }
}

function kvRow(k: string, v: string, rowClass = ""): HTMLElement {
  const row = el("div", `kv-row ${rowClass}`.trim());
  row.append(el("div", "kv-k", k));
  row.append(el("div", "kv-v", v));
  return row;
}

function renderFindings(r: Report): HTMLElement {
  const wrap = el("div", "findings");
  const findings = r.findings.filter((f) => f.count > 0);
  const custom = r.custom_findings.filter((f) => f.count > 0);
  if (findings.length === 0) {
    if (custom.length === 0) {
      wrap.append(el("div", "empty", t("report.noPersonalData")));
      return wrap;
    }
  }

  for (const f of findings) {
    const box = el("div", "finding");
    const title = el("div", "finding-title", `${piiLabel(f.category)} (${f.count})`);
    box.append(title);
    if (f.redacted_examples.length) {
      const ex = el("div", "examples");
      for (const [index, e] of f.redacted_examples.entries()) {
        const key = exampleKey(f.category, index);
        const maybeRaw = expandedRedacted.has(key) ? getRevealedValue(f.category, index) : null;
        const chip = el("button", "example-toggle", maybeRaw ?? e);
        chip.title = expandedRedacted.has(key) ? t("actions.hide") : t("actions.revealOne");
        chip.addEventListener("click", (ev) => {
          ev.preventDefault();
          void toggleRedactedExample(f.category, index);
        });
        ex.append(chip);
      }
      box.append(ex);
    }
    wrap.append(box);
  }

  for (const f of custom) {
    const box = el("div", "finding");
    const title = el("div", "finding-title custom-category");
    title.textContent = `${f.category} (${f.count})`;
    box.append(title);
    if (f.redacted_examples.length) {
      const ex = el("div", "examples");
      for (const e of f.redacted_examples) {
        ex.append(el("code", "example", e));
      }
      box.append(ex);
    }
    wrap.append(box);
  }

  if (showRevealed && r.revealed?.by_category?.length) {
    const revealed = el("div", "revealed");
    for (const cat of r.revealed.by_category) {
      if (!cat.values.length) continue;
      revealed.append(
        el("div", "revealed-title", `${piiLabel(cat.category)} (${cat.values.length})`),
      );
      const list = el("div", "revealed-values");
      for (const v of cat.values.slice(0, 50)) {
        const row = el("div", "reveal-row");
        row.append(el("code", "reveal", v.value));
        const ignoreBtn = el(
          "button",
          `mini ${v.is_ignored ? "ok" : ""}`,
          withIcon(
            v.is_ignored ? "🚫" : "🙈",
            t(v.is_ignored ? "actions.unignoreValue" : "actions.ignoreValue"),
          ),
        );
        ignoreBtn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          if (v.is_ignored) {
            await unignoreValue(cat.category, v.value);
          } else {
            await ignoreValue(cat.category, v.value);
          }
          // Refresh revealed report to update flags.
          if (selectedFileId) {
            selectedReport = await getReport(selectedFileId, true);
            showRevealed = true;
            render();
          }
        });
        row.append(ignoreBtn);
        list.append(row);
      }
      revealed.append(list);
    }
    wrap.append(revealed);
  } else if (showRevealed) {
    wrap.append(el("div", "empty", t("report.revealUnavailable")));
  }

  return wrap;
}

async function ensureNotificationPermission(): Promise<void> {
  try {
    const granted = await isPermissionGranted();
    if (!granted) {
      await requestPermission();
    }
  } catch {
    // ignore
  }
}

async function notifyFor(
  fileId: number,
  kind: "new" | "reminder",
  threshold?: string,
): Promise<void> {
  const r = await getReport(fileId, false);
  const risk = riskLabel(r.risk_level);
  const types = summarizeTypes(r);

  if (r.weak_zip_encryption) {
    sendNotification({
      title: t("notifications.weakZipTitle"),
      body: t("notifications.weakZipBody"),
    });
  }

  if (kind === "new") {
    sendNotification({
      title: t("notifications.newAlertTitle"),
      body: t("notifications.newAlertBody", { risk, types: types || "" }),
    });
  } else {
    sendNotification({
      title: t("notifications.reminderTitle", { threshold: t(`threshold.${threshold}`) }),
      body: t("notifications.reminderBody", { risk, path: r.path }),
    });
  }
}

function onGlobalKeydown(ev: KeyboardEvent): void {
  // Debug mode toggle: Ctrl+Shift+D or Cmd+Shift+D
  if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && ev.key === "D") {
    debugMode = !debugMode;
    console.log(`[pdd] Debug mode ${debugMode ? "enabled" : "disabled"}`);
    render();
    ev.preventDefault();
    return;
  }

  if (ev.key !== "Escape") return;

  if (confirmAction) {
    confirmAction = null;
    render();
    ev.preventDefault();
    return;
  }

  if (typeModal) {
    typeModal = null;
    render();
    ev.preventDefault();
    return;
  }

  if (dialog) {
    dialog = null;
    render();
    ev.preventDefault();
    return;
  }

  if (riskFilterOpen || typeFilterOpen) {
    riskFilterOpen = false;
    typeFilterOpen = false;
    render();
    ev.preventDefault();
    return;
  }

  if (menuOpen) {
    menuOpen = false;
    render();
    ev.preventDefault();
  }
}

function onGlobalClick(ev: MouseEvent): void {
  const target = ev.target as HTMLElement | null;
  if (!target) return;
  if (target.closest(".filter-dropdown")) return;
  if (!riskFilterOpen && !typeFilterOpen) return;
  riskFilterOpen = false;
  typeFilterOpen = false;
  render();
}

async function main(): Promise<void> {
  await initI18n();
  await ensureNotificationPermission();

  window.addEventListener("keydown", onGlobalKeydown);
  window.addEventListener("click", onGlobalClick);

  onLanguageChanged(() => {
    void refreshAlerts();
  });

  await refreshSettings();
  await refreshAgentsState();
  await refreshTypeDefinitions();
  await refreshAlerts();

  await listen<string>("pdd:tray", async (e) => {
    if (e.payload === "scan") {
      await onScanNow();
    } else if (e.payload === "about") {
      dialog = "about";
      aboutTab = "about";
      legalDependenciesVisible = false;
      render();
    }
  });

  await listen<AppEvent>("pdd:event", async (e) => {
    const ev = e.payload;
    if (ev.type === "scan_started") {
      isScanning = true;
      scanProgress = { processed: 0, total: 0 };
      render();
    } else if (ev.type === "scan_progress") {
      scanProgress = { processed: ev.processed, total: ev.total };
      render();
    } else if (ev.type === "scan_finished") {
      isScanning = false;
      scanProgress = null;
      await refreshAlerts();
    } else if (ev.type === "alert_created") {
      await refreshAlerts();
      await notifyFor(ev.file_id, "new");
    } else if (ev.type === "reminder_due") {
      await refreshAlerts();
      await notifyFor(ev.file_id, "reminder", ev.threshold);
    } else if (ev.type === "scan_error") {
      console.warn("scan_error", ev.path, ev.error);
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  void main();
});
