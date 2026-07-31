/** Shared URL hash state: gzip-compressed JSON in `#s=g1.…`. */

export type UrlState = {
  p?: string;
  t?: string;
  c?: string;
};

async function gzipCompress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function gzipDecompress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(encoded: string): Uint8Array {
  const pad = "=".repeat((4 - (encoded.length % 4)) % 4);
  const b64 = (encoded + pad).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

export async function encodeState(obj: unknown): Promise<string> {
  const json = new TextEncoder().encode(JSON.stringify(obj));
  return `g1.${bytesToBase64Url(await gzipCompress(json))}`;
}

export async function decodeState(encoded: string): Promise<UrlState | null> {
  try {
    if (!encoded.startsWith("g1.")) return null;
    const raw = await gzipDecompress(base64UrlToBytes(encoded.slice(3)));
    return JSON.parse(new TextDecoder().decode(raw)) as UrlState;
  } catch {
    return null;
  }
}
