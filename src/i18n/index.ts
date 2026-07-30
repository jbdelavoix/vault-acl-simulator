import { de } from "./de";
import { en } from "./en";
import { es } from "./es";
import { fr } from "./fr";
import { it } from "./it";
import {
  detectLocale,
  interpolate,
  LOCALES,
  type Dict,
  type Locale,
} from "./types";

const catalogs: Record<Locale, Dict> = { fr, en, es, it, de };

let current: Locale = "en";

export { LOCALES, detectLocale, type Locale };

export function getLocale(): Locale {
  return current;
}

export function setLocale(locale: Locale): void {
  current = locale;
  localStorage.setItem("vault-acl-lang", locale);
  const meta = LOCALES.find((l) => l.id === locale);
  if (meta) document.documentElement.lang = meta.htmlLang;
}

export function initLocale(): Locale {
  const locale = detectLocale();
  setLocale(locale);
  return locale;
}

/** Project default language when nothing is detected. */
export const DEFAULT_LOCALE: Locale = "en";


export function t(key: string, params?: Record<string, string | number>): string {
  const dict = catalogs[current] ?? en;
  const template = dict[key] ?? en[key] ?? key;
  return interpolate(template, params);
}

export function tp(key: string, n: number, params?: Record<string, string | number>): string {
  const pluralKey = n === 1 ? key : `${key}_plural`;
  const dict = catalogs[current] ?? en;
  const template = dict[pluralKey] ?? dict[key] ?? en[pluralKey] ?? en[key] ?? key;
  return interpolate(template, { n, ...params });
}
