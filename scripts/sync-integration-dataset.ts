import fs from "node:fs";
import path from "node:path";

type DatasetCase = {
  id: string;
  target_type: string;
  text: string;
  should_detect: boolean;
  origin: "fetched" | "generated";
  source_url: string;
  source_license: string;
  source_name: string;
};

type SourceSpec = {
  url: string;
  targetType: string;
  sourceName: string;
  sourceLicense: string;
};

const SOURCES: SourceSpec[] = [
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_crypto_recognizer.py",
    targetType: "bitcoin",
    sourceName: "microsoft/presidio test_crypto_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_mac_recognizer.py",
    targetType: "mac_address",
    sourceName: "microsoft/presidio test_mac_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_us_ssn_recognizer.py",
    targetType: "us_ssn",
    sourceName: "microsoft/presidio test_us_ssn_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_us_itin_recognizer.py",
    targetType: "us_itin",
    sourceName: "microsoft/presidio test_us_itin_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_us_passport_recognizer.py",
    targetType: "us_passport",
    sourceName: "microsoft/presidio test_us_passport_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_uk_nhs_recognizer.py",
    targetType: "uk_nhs",
    sourceName: "microsoft/presidio test_uk_nhs_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_uk_nino_recognizer.py",
    targetType: "uk_nino",
    sourceName: "microsoft/presidio test_uk_nino_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_es_nie_recognizer.py",
    targetType: "es_nie",
    sourceName: "microsoft/presidio test_es_nie_recognizer.py",
    sourceLicense: "MIT",
  },
  {
    url: "https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/tests/test_es_nif_recognizer.py",
    targetType: "es_dni",
    sourceName: "microsoft/presidio test_es_nif_recognizer.py",
    sourceLicense: "MIT",
  },
];

const OUTPUT_PATH = path.join(
  process.cwd(),
  "src-tauri",
  "tests",
  "data",
  "integration_dataset.jsonl",
);

function unescapePyString(raw: string): string {
  return raw
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, "\\");
}

function extractPyParamCases(content: string): Array<{ text: string; shouldDetect: boolean }> {
  const out: Array<{ text: string; shouldDetect: boolean }> = [];
  const tupleRegex = /\(\s*"((?:\\.|[^"\\])*)"\s*,\s*(\d+)/g;
  let match: RegExpExecArray | null = tupleRegex.exec(content);
  while (match !== null) {
    const text = unescapePyString(match[1]);
    const expectedLen = Number.parseInt(match[2], 10);
    out.push({ text, shouldDetect: expectedLen > 0 });
    match = tupleRegex.exec(content);
  }
  return out;
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "pdwn-dataset-sync",
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch ${url}: HTTP ${res.status}`);
  }
  return await res.text();
}

function generatedCases(): DatasetCase[] {
  const generated: Omit<DatasetCase, "id">[] = [
    {
      target_type: "ethereum",
      text: "Wallet ethereum: 0x52908400098527886E0F7030069857D2E4169EE7",
      should_detect: true,
      origin: "generated",
      source_url: "generated://erc-55",
      source_license: "generated",
      source_name: "Local generator from ERC-55 examples",
    },
    {
      target_type: "ethereum",
      text: "Invalid eth value: 0x52908400098527886E0F7030069857D2E4169EE",
      should_detect: false,
      origin: "generated",
      source_url: "generated://erc-55",
      source_license: "generated",
      source_name: "Local generator from ERC-55 examples",
    },
    {
      target_type: "fr_nir",
      text: "NIR: 180067512345678",
      should_detect: true,
      origin: "generated",
      source_url: "generated://fr-nir",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "fr_nir",
      text: "Invalid NIR: 380067512345678",
      should_detect: false,
      origin: "generated",
      source_url: "generated://fr-nir",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "fr_tva",
      text: "TVA FR: FR40303265045",
      should_detect: true,
      origin: "generated",
      source_url: "generated://fr-tva",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "fr_tva",
      text: "Invalid TVA FR: FR40A3265045",
      should_detect: false,
      origin: "generated",
      source_url: "generated://fr-tva",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "de_tax_id",
      text: "Steuer-ID: 52481530976",
      should_detect: true,
      origin: "generated",
      source_url: "generated://de-tax-id",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "de_tax_id",
      text: "Invalid Steuer-ID: 02481530976",
      should_detect: false,
      origin: "generated",
      source_url: "generated://de-tax-id",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "de_vat",
      text: "USt-IdNr: DE136695976",
      should_detect: true,
      origin: "generated",
      source_url: "generated://de-vat",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "de_vat",
      text: "Invalid USt-IdNr: DE13669597",
      should_detect: false,
      origin: "generated",
      source_url: "generated://de-vat",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "es_cif",
      text: "CIF empresa: B99286320",
      should_detect: true,
      origin: "generated",
      source_url: "generated://es-cif",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
    {
      target_type: "es_cif",
      text: "Invalid CIF: O99286320",
      should_detect: false,
      origin: "generated",
      source_url: "generated://es-cif",
      source_license: "generated",
      source_name: "Local generator from regex constraints",
    },
  ];

  return generated.map((item, index) => ({
    id: `generated_${item.target_type}_${index + 1}`,
    ...item,
  }));
}

function keepFetchedCase(
  targetType: string,
  row: { text: string; shouldDetect: boolean },
): boolean {
  switch (targetType) {
    case "bitcoin":
      if (!row.shouldDetect) {
        return row.text === "" || row.text.includes("8f953371d3e85eddb89b05ed6b9e680791055315");
      }
      return true;
    case "es_dni":
      return /\b\d{8}-?[A-Z]\b/.test(row.text);
    case "es_nie":
      return row.shouldDetect && !row.text.includes("-");
    case "mac_address":
      if (!row.shouldDetect) {
        return row.text.includes("Not a MAC") || row.text.includes("Invalid: ZZ");
      }
      return true;
    case "uk_nino":
      return row.shouldDetect;
    case "uk_nhs":
      return row.shouldDetect;
    case "us_itin":
      return row.shouldDetect;
    case "us_passport":
      return row.shouldDetect && /\b[A-Z]\d{8}\b/.test(row.text);
    case "us_ssn":
      return row.shouldDetect;
    default:
      return true;
  }
}

async function main(): Promise<void> {
  const fetchedCases: DatasetCase[] = [];

  for (const source of SOURCES) {
    const content = await fetchText(source.url);
    const rows = extractPyParamCases(content);
    rows.forEach((row, index) => {
      if (!keepFetchedCase(source.targetType, row)) {
        return;
      }
      fetchedCases.push({
        id: `${source.targetType}_fetched_${index + 1}`,
        target_type: source.targetType,
        text: row.text,
        should_detect: row.shouldDetect,
        origin: "fetched",
        source_url: source.url,
        source_license: source.sourceLicense,
        source_name: source.sourceName,
      });
    });
  }

  const combined = [...fetchedCases, ...generatedCases()];

  const dedup = new Map<string, DatasetCase>();
  for (const row of combined) {
    const key = `${row.target_type}::${row.should_detect ? 1 : 0}::${row.text}`;
    if (!dedup.has(key)) {
      dedup.set(key, row);
    }
  }

  const finalRows = [...dedup.values()].sort((a, b) => {
    const byType = a.target_type.localeCompare(b.target_type);
    if (byType !== 0) return byType;
    if (a.should_detect !== b.should_detect) return a.should_detect ? -1 : 1;
    return a.id.localeCompare(b.id);
  });

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  const jsonl = `${finalRows.map((row) => JSON.stringify(row)).join("\n")}\n`;
  fs.writeFileSync(OUTPUT_PATH, jsonl, "utf8");

  const byType = new Map<string, { pos: number; neg: number }>();
  for (const row of finalRows) {
    const bucket = byType.get(row.target_type) ?? { pos: 0, neg: 0 };
    if (row.should_detect) bucket.pos += 1;
    else bucket.neg += 1;
    byType.set(row.target_type, bucket);
  }

  console.log(`Dataset synced: ${OUTPUT_PATH}`);
  console.log(`Total rows: ${finalRows.length}`);
  for (const [type, counts] of [...byType.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    console.log(`- ${type}: +${counts.pos} / -${counts.neg}`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
