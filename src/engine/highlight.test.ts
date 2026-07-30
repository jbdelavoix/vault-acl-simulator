import { describe, expect, it } from "vitest";
import { parsePolicy } from "./parse";
import { marksFromDiagnostics, renderHighlightedSource } from "./highlight";

describe("highlight", () => {
  it("underlines wrong caps on sys/rotate", () => {
    const src = `path "sys/rotate" {
  capabilities = ["create", "read"]
}
`;
    const { diagnostics } = parsePolicy(src);
    const marks = marksFromDiagnostics(src, diagnostics);
    expect(marks.length).toBeGreaterThan(0);
    const html = renderHighlightedSource(src, marks);
    expect(html).toContain("wave-error");
    expect(html).toContain('"create"');
  });

  it("marks path with trailing slash warning", () => {
    const src = `path "secret/foo/" {
  capabilities = ["read"]
}
`;
    const { diagnostics } = parsePolicy(src);
    const marks = marksFromDiagnostics(src, diagnostics);
    const html = renderHighlightedSource(src, marks);
    expect(html).toMatch(/wave-warning.*secret\/foo\//);
  });

  it("underlines the path, not a preceding # comment", () => {
    const src = `# Mount config
path "secret/foo/" {
  capabilities = ["read"]
}
`;
    const { diagnostics, rules } = parsePolicy(src);
    expect(rules[0]?.line).toBe(2);
    const pathDiags = diagnostics.filter((d) => d.code === "trailing_slash");
    expect(pathDiags).toHaveLength(1);
    expect(pathDiags[0].line).toBe(2);
    const marks = marksFromDiagnostics(src, pathDiags);
    const html = renderHighlightedSource(src, marks);
    expect(html).not.toMatch(/wave-\w+"># Mount config/);
    expect(html).toMatch(/wave-\w+[^>]*>"secret\/foo\/"/);
  });

  it("underlines unused capabilities on known endpoints", () => {
    const src = `path "sys/rotate" {
  capabilities = ["create", "update", "sudo"]
}
`;
    const { diagnostics } = parsePolicy(src);
    const marks = marksFromDiagnostics(src, diagnostics);
    const html = renderHighlightedSource(src, marks);
    expect(html).toMatch(/wave-warning[^>]*>"create"/);
  });
});
