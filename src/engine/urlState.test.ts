import { describe, expect, it } from "vitest";
import { decodeState, encodeState } from "./urlState";

describe("urlState", () => {
  it("round-trips gzip state", async () => {
    const input = {
      p: 'path "secret/data/apps/*" {\n  capabilities = ["read", "list"]\n}\n'.repeat(20),
      t: "secret/data/apps/foo\nsecret/data/apps/bar",
      c: "read" as const,
    };
    const encoded = await encodeState(input);
    expect(encoded.startsWith("g1.")).toBe(true);
    const decoded = await decodeState(encoded);
    expect(decoded).toEqual(input);
  });

  it("compresses better than raw base64 for repetitive HCL", async () => {
    const input = {
      p: 'path "secret/data/apps/*" {\n  capabilities = ["create", "read", "update", "delete", "list"]\n}\n'.repeat(
        30,
      ),
      t: "secret/data/apps/x",
      c: "any",
    };
    const json = new TextEncoder().encode(JSON.stringify(input));
    let rawB64 = "";
    for (const b of json) rawB64 += String.fromCharCode(b);
    const legacyLen = btoa(rawB64).length;
    const compressed = await encodeState(input);
    expect(compressed.length).toBeLessThan(legacyLen * 0.5);
  });

  it("rejects non-g1 payloads", async () => {
    expect(await decodeState("r1.e30")).toBeNull();
    expect(await decodeState("not-valid")).toBeNull();
  });
});
