import fs from "node:fs";
import path from "node:path";

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function flattenKeys(obj: Json, prefix = ""): string[] {
  const keys: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    const next = prefix ? `${prefix}.${k}` : k;
    if (isObject(v)) {
      keys.push(...flattenKeys(v, next));
    } else {
      keys.push(next);
    }
  }
  return keys;
}

function readJson(filePath: string): Json {
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isObject(parsed)) {
    throw new Error(`Invalid JSON root (expected object): ${filePath}`);
  }
  return parsed;
}

const localesDir = path.join(process.cwd(), "src", "locales");
const localeFiles = fs
  .readdirSync(localesDir)
  .filter((f) => f.endsWith(".json"))
  .sort();

if (localeFiles.length === 0) {
  console.error("No locale JSON files found in src/locales");
  process.exit(1);
}

const locales = localeFiles.map((f) => ({
  name: path.basename(f, ".json"),
  filePath: path.join(localesDir, f),
}));

const base = locales.find((l) => l.name === "en") ?? locales[0];
const baseObj = readJson(base.filePath);
const baseKeys = new Set(flattenKeys(baseObj));

let ok = true;

for (const loc of locales) {
  const obj = readJson(loc.filePath);
  const keys = new Set(flattenKeys(obj));

  const missing: string[] = [];
  for (const k of baseKeys) {
    if (!keys.has(k)) missing.push(k);
  }

  const extra: string[] = [];
  for (const k of keys) {
    if (!baseKeys.has(k)) extra.push(k);
  }

  if (missing.length || extra.length) {
    ok = false;
    console.error(`i18n mismatch in ${loc.name}`);
    if (missing.length) {
      console.error(`  missing (${missing.length}): ${missing.slice(0, 50).join(", ")}`);
      if (missing.length > 50) console.error("  ...");
    }
    if (extra.length) {
      console.error(`  extra (${extra.length}): ${extra.slice(0, 50).join(", ")}`);
      if (extra.length > 50) console.error("  ...");
    }
  }
}

if (!ok) {
  process.exit(1);
}

console.log(`i18n OK (${locales.length} locales, base=${base.name})`);
