import { listen } from "@tauri-apps/api/event";
import { documentDir, downloadDir, homeDir } from "@tauri-apps/api/path";
import { open } from "@tauri-apps/plugin-dialog";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";

import {
  type CustomDetector,
  type EntitySetting,
  type NewCustomDetector,
  type Report,
  type Settings,
  type UiAlert,
  clearAlerts,
  createCustomDetector,
  deleteCustomDetector,
  deleteFileToTrash,
  getEntitySettings,
  getReport,
  getSettings,
  ignoreFile,
  listAlerts,
  listCustomDetectors,
  markValueAsMine,
  openInFileManager,
  scanNow,
  setSettings,
  stopScan,
  unignoreFile,
  unmarkValueAsMine,
  updateCustomDetector,
  updateEntityEnabled,
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
let reportPanelVisible = true;
let reportLoadError: string | null = null;
const selectedRiskFilters = new Set<UiAlert["risk_level"]>();
const selectedTypeFilters = new Set<string>();
let riskFilterOpen = false;
let typeFilterOpen = false;
let sortBy: SortMode = "risk_desc";
let showIgnored = false;
let isScanning = false;
let scanProgress: { processed: number; total: number } | null = null;
let menuOpen = false;
let dialog: "about" | "types" | null = null;
let aboutTab: "about" | "legal" = "about";
let typesTab: "standard" | "custom" = "standard";
let customDetectors: CustomDetector[] = [];
let entitySettings: EntitySetting[] = [];
let entityConfigOpen: string | null = null;
let customFormMode: "create" | "edit" | null = null;
let customFormId: number | null = null;
let customFormError: string | null = null;
let customForm: NewCustomDetector = {
  name: "",
  risk_level: "medium",
  filename_regex: "",
  field_name_regex: "",
  value_regex: "",
  enabled: true,
};
type ConfirmAction =
  | { kind: "scanRunning" }
  | { kind: "stopScan" }
  | { kind: "deleteFile"; fileId: number }
  | { kind: "deleteCustom"; detectorId: number; detectorName: string };
let confirmAction: ConfirmAction | null = null;
const expandedRedacted = new Set<string>();
let debugMode = false;

type SortMode = "risk_desc" | "risk_asc" | "recent" | "type";

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

function alertHasType(a: UiAlert, type: string): boolean {
  if (type === "weak_archive_encryption") return a.weak_zip_encryption;
  return (
    a.pii_summary.some((f) => f.category === type && f.count > 0) ||
    a.custom_summary.some((f) => f.category === type && f.count > 0)
  );
}

function primaryType(a: UiAlert): string {
  if (a.weak_zip_encryption) return piiLabel("weak_archive_encryption");
  const top = [...a.pii_summary]
    .filter((f) => f.count > 0 && f.category !== "file_name_signal")
    .sort((x, y) => y.count - x.count)[0];
  if (!top) return piiLabel("file_name_signal");
  return piiLabel(top.category);
}

function visibleAlerts(): UiAlert[] {
  let items = alerts.filter((a) => (showIgnored ? true : !a.ignored));

  if (selectedRiskFilters.size > 0) {
    items = items.filter((a) => selectedRiskFilters.has(a.risk_level));
  }
  if (selectedTypeFilters.size > 0) {
    items = items.filter((a) =>
      Array.from(selectedTypeFilters).some((selectedType) => alertHasType(a, selectedType)),
    );
  }

  items = [...items].sort((a, b) => {
    if (sortBy === "risk_desc") {
      return riskRank(b.risk_level) - riskRank(a.risk_level) || b.last_seen_at - a.last_seen_at;
    }
    if (sortBy === "risk_asc") {
      return riskRank(a.risk_level) - riskRank(b.risk_level) || b.last_seen_at - a.last_seen_at;
    }
    if (sortBy === "recent") {
      return b.last_seen_at - a.last_seen_at;
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

async function refreshAlerts(): Promise<void> {
  debugLog("refreshAlerts:start");
  alerts = await listAlerts();
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

async function refreshCustomDetectors(): Promise<void> {
  try {
    customDetectors = await listCustomDetectors();
  } catch {
    customDetectors = [];
  }
  render();
}

async function refreshEntitySettings(): Promise<void> {
  try {
    entitySettings = await getEntitySettings();
  } catch {
    entitySettings = [];
  }
  render();
}

async function toggleEntityEnabled(entityType: string, enabled: boolean): Promise<void> {
  try {
    await updateEntityEnabled(entityType, enabled);
    await refreshEntitySettings();
  } catch (error) {
    console.error("Failed to update entity:", error);
  }
}

async function selectFile(fileId: number): Promise<void> {
  debugLog("selectFile:start", { fileId });
  reportPanelVisible = true;
  selectedFileId = fileId;
  showRevealed = false;
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
  render();
}

async function onDelete(): Promise<void> {
  if (!selectedFileId) return;
  confirmAction = { kind: "deleteFile", fileId: selectedFileId };
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

function toDetectorInput(base?: CustomDetector): NewCustomDetector {
  return {
    name: base?.name ?? "",
    risk_level: base?.risk_level ?? "medium",
    filename_regex: base?.filename_regex ?? "",
    field_name_regex: base?.field_name_regex ?? "",
    value_regex: base?.value_regex ?? "",
    enabled: base?.enabled ?? true,
  };
}

function openCreateCustomForm(): void {
  customFormMode = "create";
  customFormId = null;
  customFormError = null;
  customForm = toDetectorInput();
  render();
}

function openEditCustomForm(det: CustomDetector): void {
  customFormMode = "edit";
  customFormId = det.id;
  customFormError = null;
  customForm = toDetectorInput(det);
  render();
}

function closeCustomForm(): void {
  customFormMode = null;
  customFormId = null;
  customFormError = null;
  customForm = toDetectorInput();
}

async function submitCustomForm(): Promise<void> {
  try {
    if (customFormMode === "create") {
      await createCustomDetector(customForm);
    } else if (customFormMode === "edit" && customFormId !== null) {
      await updateCustomDetector(customFormId, customForm);
    }
    closeCustomForm();
    await refreshCustomDetectors();
  } catch (error) {
    customFormError = error instanceof Error ? error.message : String(error);
    render();
  }
}

async function onDeleteCustomDetector(det: CustomDetector): Promise<void> {
  confirmAction = { kind: "deleteCustom", detectorId: det.id, detectorName: det.name };
  render();
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
  await deleteCustomDetector(action.detectorId);
  await refreshCustomDetectors();
}

function render(): void {
  const root = el("div", "app");

  const header = el("header", "top");
  const brand = el("div", "brand");
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
      menuOpen = false;
      render();
    });
    menu.append(aboutBtn);
    const customBtn = el("button", "menu-item", t("menu.types"));
    customBtn.addEventListener("click", () => {
      dialog = "types";
      typesTab = "standard";
      menuOpen = false;
      void refreshCustomDetectors();
      render();
    });
    menu.append(customBtn);
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

  left.append(filters);

  const list = el("div", "alert-list");
  const visible = visibleAlerts();
  if (visible.length === 0) {
    list.append(el("div", "empty", t("alerts.empty")));
  } else {
    for (const a of visible) {
      const item = el("button", "alert-item");
      if (a.file_id === selectedFileId) item.dataset.selected = "true";
      if (a.ignored) item.dataset.ignored = "true";

      const topRow = el("div", "alert-top");
      const nameEl = el("div", "alert-path", fileNameFromPath(a.path));
      nameEl.title = a.path;
      topRow.append(nameEl);

      const badge = el("div", `badge badge-${a.risk_level}`, riskLabel(a.risk_level));
      topRow.append(badge);
      item.append(topRow);

      const meta = el("div", "alert-meta");
      meta.append(el("div", "alert-types", summarizeTypes(a) || piiLabel("file_name_signal")));
      meta.append(el("div", "alert-age", fmtAge(a.last_seen_at)));
      item.append(meta);

      item.addEventListener("click", () => void selectFile(a.file_id));
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
      reportLoadError = null;
      expandedRedacted.clear();
      render();
    });
    reportHeader.append(closeReportBtn);
    right.append(reportHeader);
    const body = el("div", "report");
    if (reportLoadError) {
      body.append(el("div", "warn", t("report.loadError", { error: reportLoadError })));
    } else if (!selectedReport) {
      body.append(el("div", "empty", t("report.select")));
    } else {
      const r = selectedReport;
      const kv = el("div", "kv");
      kv.append(kvRow(t("report.fileName"), fileNameFromPath(r.path)));
      kv.append(kvRow(t("report.path"), r.path));
      kv.append(kvRow(t("report.size"), fmtBytes(r.size)));
      kv.append(kvRow(t("report.modified"), fmtDate(r.mtime)));
      kv.append(kvRow(t("alerts.risk"), `${riskLabel(r.risk_level)} (${r.risk_score})`));
      body.append(kv);

      if (r.weak_zip_encryption) {
        const warn = el("div", "warn");
        warn.append(el("div", "warn-title", t("report.weakEncryption")));
        warn.append(el("div", "warn-body", t("report.weakEncryptionDesc")));
        body.append(warn);
      }

      body.append(el("h3", "sub", t("report.findings")));
      body.append(renderFindings(r));

      body.append(el("h3", "sub", t("report.reasons")));
      const reasons = el("ul", "reasons");
      for (const reason of r.reasons.slice(0, 12)) {
        const li = document.createElement("li");
        const vars = { ...(reason.vars ?? {}) } as Record<string, unknown>;
        if (typeof vars.category === "string") {
          vars.category = piiLabel(vars.category);
        }
        if (typeof vars.risk === "string") {
          vars.risk = riskLabel(vars.risk as UiAlert["risk_level"]);
        }
        li.textContent = t(reason.key, vars as never);
        reasons.append(li);
      }
      body.append(reasons);

      body.append(el("h3", "sub", t("report.suggestion")));
      body.append(el("div", "suggestion", r.suggestion));

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
      ignoreBtn.addEventListener("click", () => void onIgnoreToggle());
      actions.append(ignoreBtn);

      const revealAllowed = canRevealReport(r);
      const revealBtn = el(
        "button",
        "btn",
        withIcon(showRevealed ? "🙈" : "👁", t(showRevealed ? "actions.hide" : "actions.reveal")),
      );
      (revealBtn as HTMLButtonElement).disabled = !revealAllowed;
      revealBtn.addEventListener("click", () => void toggleReveal());
      actions.append(revealBtn);
      if (!revealAllowed) {
        body.append(el("div", "empty", t("report.revealUnavailable")));
      }

      const deleteBtn = el("button", "btn danger", withIcon("🗑", t("actions.delete")));
      deleteBtn.addEventListener("click", () => void onDelete());
      actions.append(deleteBtn);

      body.append(actions);
    }
    right.append(body);
    main.append(right);
  }

  root.append(main);

  if (dialog) {
    const overlay = el("div", "overlay");
    const card = el("div", "dialog");
    const head = el("div", "dialog-head");
    head.append(el("h3", "dialog-title", dialog === "types" ? t("menu.types") : t("menu.about")));
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
        body.append(el("p", "", t("about.description")));
        body.append(el("p", "", `${t("about.authorLabel")} ${t("about.author")}`));
      } else {
        body.append(el("p", "", t("about.legalText")));
      }
    } else if (dialog === "types") {
      const tabs = el("div", "dialog-tabs");
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
      body.append(tabs);

      if (typesTab === "standard") {
        // Load entity settings if not already loaded
        if (entitySettings.length === 0) {
          void refreshEntitySettings();
        }

        // Separate pure and contextual entities
        const pureEntities = entitySettings.filter((e) => e.entity_category === "pure");
        const contextualEntities = entitySettings.filter((e) => e.entity_category === "contextual");

        // Pure Entities Section
        if (pureEntities.length > 0) {
          body.append(el("h4", "entity-section-title", t("entities.pureTitle")));
          const pureList = el("div", "entity-list");

          for (const entity of pureEntities) {
            const row = el("div", "entity-row");

            // Enable/disable toggle
            const toggle = el(
              "button",
              `mini ${entity.enabled ? "enabled" : "disabled"}`,
              entity.enabled ? "✓" : "○",
            );
            toggle.addEventListener(
              "click",
              () => void toggleEntityEnabled(entity.entity_type, !entity.enabled),
            );
            row.append(toggle);

            // Entity info
            const info = el("div", "entity-info");
            const name = el(
              "div",
              "entity-name",
              t(`entities.types.${entity.entity_type}`) || entity.entity_type,
            );
            info.append(name);

            const desc = el(
              "div",
              "entity-desc",
              t(`entities.descriptions.${entity.entity_type}`) || "",
            );
            info.append(desc);

            // Locale badge if applicable
            if (entity.locale_requirement) {
              const badge = el("span", "locale-badge", t("entities.localeBadge"));
              info.append(badge);
            }

            row.append(info);
            pureList.append(row);
          }
          body.append(pureList);
        }

        // Contextual Entities Section
        if (contextualEntities.length > 0) {
          body.append(el("h4", "entity-section-title", t("entities.contextualTitle")));
          const contextualList = el("div", "entity-list");

          for (const entity of contextualEntities) {
            const row = el("div", "entity-row");

            // Enable/disable toggle
            const toggle = el(
              "button",
              `mini ${entity.enabled ? "enabled" : "disabled"}`,
              entity.enabled ? "✓" : "○",
            );
            toggle.addEventListener(
              "click",
              () => void toggleEntityEnabled(entity.entity_type, !entity.enabled),
            );
            row.append(toggle);

            // Entity info
            const info = el("div", "entity-info");
            const name = el(
              "div",
              "entity-name",
              t(`entities.types.${entity.entity_type}`) || entity.entity_type,
            );
            info.append(name);

            const desc = el(
              "div",
              "entity-desc",
              t(`entities.descriptions.${entity.entity_type}`) || "",
            );
            info.append(desc);

            // Threshold info
            if (entity.threshold) {
              const threshold = el(
                "div",
                "entity-threshold",
                `≥ ${Math.round(entity.threshold * 100)}% confidence`,
              );
              info.append(threshold);
            }

            // Configure button
            const configBtn = el("button", "mini", t("entities.configure"));
            configBtn.addEventListener("click", () => {
              entityConfigOpen =
                entityConfigOpen === entity.entity_type ? null : entity.entity_type;
              render();
            });
            row.append(configBtn);

            contextualList.append(row);

            // Configuration panel (if open)
            if (entityConfigOpen === entity.entity_type) {
              const configPanel = el("div", "entity-config-panel");

              // Positive indicators
              configPanel.append(el("label", "config-label", t("entities.positiveIndicators")));
              const posInput = document.createElement("input");
              posInput.className = "config-input";
              posInput.value = entity.positive_indicators || "";
              posInput.placeholder = "word1, word2, word3...";
              configPanel.append(posInput);

              // Negative indicators
              configPanel.append(el("label", "config-label", t("entities.negativeIndicators")));
              const negInput = document.createElement("input");
              negInput.className = "config-input";
              negInput.value = entity.negative_indicators || "";
              negInput.placeholder = "word1, word2, word3...";
              configPanel.append(negInput);

              // Threshold slider
              configPanel.append(el("label", "config-label", t("entities.threshold")));
              const thresholdContainer = el("div", "threshold-container");
              const thresholdValue = entity.threshold || 0.75;
              const thresholdSlider = document.createElement("input");
              thresholdSlider.type = "range";
              thresholdSlider.min = "0.5";
              thresholdSlider.max = "0.95";
              thresholdSlider.step = "0.05";
              thresholdSlider.value = thresholdValue.toString();
              thresholdSlider.className = "threshold-slider";
              thresholdContainer.append(thresholdSlider);
              const thresholdDisplay = el(
                "span",
                "threshold-display",
                `${Math.round(thresholdValue * 100)}%`,
              );
              thresholdSlider.addEventListener("input", () => {
                thresholdDisplay.textContent = `${Math.round(Number.parseFloat(thresholdSlider.value) * 100)}%`;
              });
              thresholdContainer.append(thresholdDisplay);
              configPanel.append(thresholdContainer);

              // Action buttons
              const actions = el("div", "config-actions");
              const saveBtn = el("button", "btn", t("common.confirm"));
              saveBtn.addEventListener("click", async () => {
                try {
                  const { updateContextualEntity } = await import("./api");
                  await updateContextualEntity(
                    entity.entity_type,
                    posInput.value || null,
                    negInput.value || null,
                    Number.parseFloat(thresholdSlider.value),
                  );
                  entityConfigOpen = null;
                  await refreshEntitySettings();
                } catch (error) {
                  console.error("Failed to update entity:", error);
                }
              });
              actions.append(saveBtn);

              const cancelBtn = el("button", "btn", t("common.cancel"));
              cancelBtn.addEventListener("click", () => {
                entityConfigOpen = null;
                render();
              });
              actions.append(cancelBtn);
              configPanel.append(actions);

              contextualList.append(configPanel);
            }
          }
          body.append(contextualList);
        }
      } else {
        const add = el("button", "btn", withIcon("＋", t("custom.add")));
        add.addEventListener("click", () => openCreateCustomForm());
        body.append(add);

        if (customFormMode) {
          const form = el("div", "custom-form");
          form.append(el("label", "custom-label", t("custom.namePrompt")));
          const nameInput = document.createElement("input");
          nameInput.className = "custom-input";
          nameInput.value = customForm.name;
          nameInput.addEventListener("input", () => {
            customForm.name = nameInput.value;
          });
          form.append(nameInput);

          form.append(el("label", "custom-label", t("custom.riskPrompt")));
          const riskSelect = document.createElement("select");
          riskSelect.className = "custom-input";
          for (const level of ["low", "medium", "high", "critical"]) {
            const opt = document.createElement("option");
            opt.value = level;
            opt.textContent = riskLabel(level as UiAlert["risk_level"]);
            if (customForm.risk_level === level) opt.selected = true;
            riskSelect.append(opt);
          }
          riskSelect.addEventListener("change", () => {
            customForm.risk_level = riskSelect.value as NewCustomDetector["risk_level"];
          });
          form.append(riskSelect);

          form.append(el("label", "custom-label", t("custom.filenamePrompt")));
          const fInput = document.createElement("input");
          fInput.className = "custom-input";
          fInput.value = customForm.filename_regex ?? "";
          fInput.addEventListener("input", () => {
            customForm.filename_regex = fInput.value;
          });
          form.append(fInput);

          form.append(el("label", "custom-label", t("custom.fieldPrompt")));
          const kInput = document.createElement("input");
          kInput.className = "custom-input";
          kInput.value = customForm.field_name_regex ?? "";
          kInput.addEventListener("input", () => {
            customForm.field_name_regex = kInput.value;
          });
          form.append(kInput);

          form.append(el("label", "custom-label", t("custom.valuePrompt")));
          const vInput = document.createElement("input");
          vInput.className = "custom-input";
          vInput.value = customForm.value_regex ?? "";
          vInput.addEventListener("input", () => {
            customForm.value_regex = vInput.value;
          });
          form.append(vInput);

          if (customFormError) {
            form.append(el("div", "warn", customFormError));
          }
          const formActions = el("div", "actions");
          const saveBtn = el("button", "btn", t("common.confirm"));
          saveBtn.addEventListener("click", () => void submitCustomForm());
          formActions.append(saveBtn);
          const cancelBtn = el("button", "btn", t("common.cancel"));
          cancelBtn.addEventListener("click", () => {
            closeCustomForm();
            render();
          });
          formActions.append(cancelBtn);
          form.append(formActions);
          body.append(form);
        }

        const list = el("div", "custom-list");
        if (customDetectors.length === 0) {
          list.append(el("div", "empty", t("custom.empty")));
        } else {
          for (const det of customDetectors) {
            const row = el("div", "custom-row");
            const label = el("div", "custom-name", det.name);
            row.append(label);
            const meta = el(
              "div",
              "custom-meta",
              [
                `${t("custom.metaRisk")}: ${riskLabel(det.risk_level)}`,
                det.filename_regex ? t("custom.metaFilename") : "",
                det.field_name_regex ? t("custom.metaField") : "",
                det.value_regex ? t("custom.metaValue") : "",
              ]
                .filter(Boolean)
                .join(" / ") || "-",
            );
            row.append(meta);
            const toggle = el(
              "button",
              "mini",
              det.enabled ? t("custom.disable") : t("custom.enable"),
            );
            toggle.addEventListener("click", async () => {
              await updateCustomDetector(det.id, {
                name: det.name,
                risk_level: det.risk_level,
                filename_regex: det.filename_regex,
                field_name_regex: det.field_name_regex,
                value_regex: det.value_regex,
                enabled: !det.enabled,
              });
              await refreshCustomDetectors();
            });
            row.append(toggle);
            const edit = el("button", "mini", t("custom.edit"));
            edit.addEventListener("click", () => openEditCustomForm(det));
            row.append(edit);
            const del = el("button", "mini", t("custom.delete"));
            del.addEventListener("click", () => void onDeleteCustomDetector(det));
            row.append(del);
            list.append(row);
          }
        }
        body.append(list);
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
    } else {
      message = t("custom.deleteConfirm", { name: confirmAction.detectorName });
    }
    body.append(el("p", "", message));
    const actions = el("div", "actions");
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

  appEl.replaceChildren(root);
}

function kvRow(k: string, v: string): HTMLElement {
  const row = el("div", "kv-row");
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
      wrap.append(el("div", "empty", "-"));
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
        const btn = el(
          "button",
          `mini ${v.is_mine ? "ok" : ""}`,
          withIcon(
            v.is_mine ? "👤" : "✓",
            t(v.is_mine ? "actions.unmarkMine" : "actions.markMine"),
          ),
        );
        btn.addEventListener("click", async (e) => {
          e.preventDefault();
          e.stopPropagation();
          if (v.is_mine) {
            await unmarkValueAsMine(cat.category, v.value);
          } else {
            await markValueAsMine(cat.category, v.value);
          }
          // Refresh revealed report to update flags.
          if (selectedFileId) {
            selectedReport = await getReport(selectedFileId, true);
            showRevealed = true;
            render();
          }
        });
        row.append(btn);
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

  if (customFormMode) {
    closeCustomForm();
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
  await refreshCustomDetectors();
  await refreshAlerts();

  await listen<string>("pdd:tray", async (e) => {
    if (e.payload === "scan") {
      await onScanNow();
    } else if (e.payload === "about") {
      dialog = "about";
      aboutTab = "about";
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
