/** Shared URL hash state: brotli + base64url. */

export type UrlState = {
  p?: string;
  t?: string;
  c?: string;
};

async function brotliCompress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)])
    .stream()
    .pipeThrough(new CompressionStream("brotli" as CompressionFormat));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function brotliDecompress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)])
    .stream()
    .pipeThrough(new DecompressionStream("brotli" as CompressionFormat));
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
  return bytesToBase64Url(await brotliCompress(json));
}

export async function decodeState(encoded: string): Promise<UrlState | null> {
  try {
    const raw = await brotliDecompress(base64UrlToBytes(encoded));
    return JSON.parse(new TextDecoder().decode(raw)) as UrlState;
  } catch {
    return null;
  }
}
