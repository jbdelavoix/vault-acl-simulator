import type { Diagnostic, Severity } from "./types";

export interface TextMark {
  start: number;
  end: number;
  severity: Severity;
  message: string;
}

function lineOffsets(source: string): number[] {
  const offsets = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\n") offsets.push(i + 1);
  }
  return offsets;
}

function lineRange(source: string, line: number): { start: number; end: number } | null {
  const offsets = lineOffsets(source);
  if (line < 1 || line > offsets.length) return null;
  const start = offsets[line - 1];
  const end = line < offsets.length ? offsets[line] - 1 : source.length;
  return { start, end };
}

function capabilitiesArrayRange(
  source: string,
  fromLine: number,
): { start: number; end: number } | null {
  const lr = lineRange(source, fromLine);
  if (!lr) return null;
  const slice = source.slice(lr.start);
  const m = slice.match(/capabilities\s*=\s*\[[\s\S]*?\]/);
  if (!m || m.index === undefined) return null;
  return { start: lr.start + m.index, end: lr.start + m.index + m[0].length };
}

function markQuotedTokens(
  source: string,
  range: { start: number; end: number },
  tokens: string[],
  severity: Severity,
  message: string,
): TextMark[] {
  const chunk = source.slice(range.start, range.end);
  const marks: TextMark[] = [];
  for (const token of tokens) {
    const re = new RegExp(`"${token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(chunk))) {
      marks.push({
        start: range.start + m.index,
        end: range.start + m.index + m[0].length,
        severity,
        message,
      });
    }
  }
  return marks;
}

function pathLiteralRange(source: string, line: number, path?: string): TextMark | null {
  const lr = lineRange(source, line);
  if (!lr) return null;
  const lineText = source.slice(lr.start, lr.end);
  if (path) {
    const needle = `"${path}"`;
    const idx = lineText.indexOf(needle);
    if (idx >= 0) {
      return {
        start: lr.start + idx,
        end: lr.start + idx + needle.length,
        severity: "error",
        message: "",
      };
    }
    const loose = lineText.match(/path\s+("([^"]*)"|'([^']*)')/);
    if (loose && loose.index !== undefined) {
      return {
        start: lr.start + loose.index + loose[0].indexOf(loose[1]),
        end: lr.start + loose.index + loose[0].indexOf(loose[1]) + loose[1].length,
        severity: "error",
        message: "",
      };
    }
  }
  const pathMatch = lineText.match(/path\s+("([^"]*)"|'([^']*)')/);
  if (pathMatch && pathMatch.index !== undefined) {
    const lit = pathMatch[1];
    const at = pathMatch.index + pathMatch[0].indexOf(lit);
    return {
      start: lr.start + at,
      end: lr.start + at + lit.length,
      severity: "error",
      message: "",
    };
  }
  const trimmedStart = lr.start + (lineText.match(/^\s*/)?.[0].length ?? 0);
  const trimmedEnd = lr.end - (lineText.match(/\s*$/)?.[0].length ?? 0);
  if (trimmedEnd <= trimmedStart) return null;
  return { start: trimmedStart, end: trimmedEnd, severity: "error", message: "" };
}

export function marksFromDiagnostics(
  source: string,
  diags: Diagnostic[],
  formatMessage: (d: Diagnostic) => string = (d) => d.code,
): TextMark[] {
  const marks: TextMark[] = [];

  for (const d of diags) {
    if (!d.line) continue;
    const msg = formatMessage(d);
    const capsRange = capabilitiesArrayRange(source, d.line);

    if (capsRange && d.code === "invalid_capability") {
      const cap = String(d.params?.cap ?? "");
      if (cap) {
        marks.push(...markQuotedTokens(source, capsRange, [cap], d.severity, msg));
        continue;
      }
    }

    if (capsRange && d.code === "missing_caps") {
      const required = new Set(
        String(d.params?.required ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      );
      const chunk = source.slice(capsRange.start, capsRange.end);
      const present = [...chunk.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
      const wrong = present.filter((c) => !required.has(c) && c !== "sudo");
      if (wrong.length) {
        marks.push(...markQuotedTokens(source, capsRange, wrong, d.severity, msg));
      } else {
        marks.push({ ...capsRange, severity: d.severity, message: msg });
      }
      continue;
    }

    if (capsRange && d.code === "unused_caps") {
      const unused = String(d.params?.unused ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (unused.length) {
        marks.push(...markQuotedTokens(source, capsRange, unused, d.severity, msg));
      } else {
        marks.push({ ...capsRange, severity: d.severity, message: msg });
      }
      continue;
    }

    if (capsRange && d.code === "missing_sudo") {
      marks.push({ ...capsRange, severity: d.severity, message: msg });
      continue;
    }

    const pathMark = pathLiteralRange(source, d.line, d.path);
    if (pathMark) {
      marks.push({ ...pathMark, severity: d.severity, message: msg });
      continue;
    }

    const lr = lineRange(source, d.line);
    if (lr) marks.push({ ...lr, severity: d.severity, message: msg });
  }

  marks.sort((a, b) => a.start - b.start || b.end - a.end);
  return marks;
}

export function renderHighlightedSource(source: string, marks: TextMark[]): string {
  if (!source) return "";
  if (marks.length === 0) {
    return escape(source);
  }

  const rank: Record<Severity, number> = { error: 3, warning: 2, info: 1 };
  const points: Array<{ at: number; kind: "start" | "end"; mark: TextMark }> = [];
  for (const m of marks) {
    if (m.end <= m.start) continue;
    points.push({ at: m.start, kind: "start", mark: m });
    points.push({ at: m.end, kind: "end", mark: m });
  }
  points.sort((a, b) => a.at - b.at || (a.kind === "end" ? -1 : 1));

  let html = "";
  let cursor = 0;
  const active: TextMark[] = [];

  const top = () =>
    active.length
      ? active.reduce((best, m) => (rank[m.severity] > rank[best.severity] ? m : best))
      : null;

  const flush = (until: number) => {
    if (until <= cursor) return;
    const text = escape(source.slice(cursor, until));
    const m = top();
    if (m) {
      html += `<span class="wave wave-${m.severity}" title="${escapeAttr(m.message)}">${text}</span>`;
    } else {
      html += text;
    }
    cursor = until;
  };

  for (const p of points) {
    flush(p.at);
    if (p.kind === "start") active.push(p.mark);
    else {
      const idx = active.indexOf(p.mark);
      if (idx >= 0) active.splice(idx, 1);
    }
  }
  flush(source.length);
  return html;
}

function escape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeAttr(s: string): string {
  return escape(s).replace(/"/g, "&quot;");
}

export function lineSeverities(diags: Diagnostic[]): Map<number, Severity> {
  const rank: Record<Severity, number> = { error: 3, warning: 2, info: 1 };
  const map = new Map<number, Severity>();
  for (const d of diags) {
    if (!d.line) continue;
    const prev = map.get(d.line);
    if (!prev || rank[d.severity] > rank[prev]) map.set(d.line, d.severity);
  }
  return map;
}
