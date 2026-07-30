export type Locale = "fr" | "en" | "es" | "it" | "de";

export const LOCALES: Array<{ id: Locale; label: string; htmlLang: string }> = [
  { id: "fr", label: "FR", htmlLang: "fr" },
  { id: "en", label: "EN", htmlLang: "en-US" },
  { id: "es", label: "ES", htmlLang: "es" },
  { id: "it", label: "IT", htmlLang: "it" },
  { id: "de", label: "DE", htmlLang: "de" },
];

export type Dict = Record<string, string>;

export function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, key: string) =>
    params[key] !== undefined ? String(params[key]) : `{${key}}`,
  );
}

export function detectLocale(): Locale {
  const saved = localStorage.getItem("vault-acl-lang") as Locale | null;
  if (saved && LOCALES.some((l) => l.id === saved)) return saved;

  const langs = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const raw of langs) {
    const lower = raw.toLowerCase();
    if (lower.startsWith("fr")) return "fr";
    if (lower.startsWith("es")) return "es";
    if (lower.startsWith("it")) return "it";
    if (lower.startsWith("de")) return "de";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}
