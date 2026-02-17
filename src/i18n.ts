import i18next from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import ar from "./locales/ar.json";
import de from "./locales/de.json";
import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";

export type AppLanguage = "en" | "fr" | "ar" | "es" | "de";

const SUPPORTED: AppLanguage[] = ["fr", "en", "ar", "es", "de"];

function normalizeLang(lang: string | undefined | null): AppLanguage {
  const raw = (lang ?? "").toLowerCase();
  const short = raw.split("-")[0] as AppLanguage;
  if (SUPPORTED.includes(short)) return short;
  return "fr";
}

export async function initI18n(): Promise<void> {
  await i18next.use(LanguageDetector).init({
    fallbackLng: "fr",
    supportedLngs: SUPPORTED,
    nonExplicitSupportedLngs: true,
    cleanCode: true,
    load: "languageOnly",
    detection: {
      order: ["navigator"],
      caches: [],
    },
    resources: {
      en: { translation: en },
      fr: { translation: fr },
      ar: { translation: ar },
      es: { translation: es },
      de: { translation: de },
    },
    interpolation: { escapeValue: false },
  });

  const lang = normalizeLang(i18next.language);
  if (lang !== i18next.language) {
    await i18next.changeLanguage(lang);
  }
  applyDirection(lang);
  i18next.on("languageChanged", (l) => applyDirection(normalizeLang(l)));
}

function applyDirection(lang: AppLanguage): void {
  document.documentElement.lang = lang;
  const rtl = lang === "ar";
  document.documentElement.dir = rtl ? "rtl" : "ltr";
  document.documentElement.dataset.lang = lang;
}

export function t(key: string, vars?: Record<string, string | number>): string {
  return i18next.t(key, vars);
}

export function getLanguage(): AppLanguage {
  return normalizeLang(i18next.language);
}

export function onLanguageChanged(cb: (lang: AppLanguage) => void): () => void {
  const handler = (l: string) => cb(normalizeLang(l));
  i18next.on("languageChanged", handler);
  return () => i18next.off("languageChanged", handler);
}
