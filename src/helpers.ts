import type { BytesOutput, FileInput } from "./types.js";

/** Standard base64 of `bytes` (chunked so large arrays do not overflow `String.fromCharCode`). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Inline file argument from an in-memory blob. Fine for small data (text, stamps, signatures);
 * for real files pass `{ path }` instead so nothing large crosses IPC.
 */
export async function toFileInput(
  source: Blob | Uint8Array | ArrayBuffer,
  name?: string,
  mimeType?: string,
): Promise<FileInput> {
  let bytes: Uint8Array;
  if (source instanceof Uint8Array) bytes = source;
  else if (source instanceof ArrayBuffer) bytes = new Uint8Array(source);
  else bytes = new Uint8Array(await source.arrayBuffer());
  const mime = mimeType ?? (source instanceof Blob && source.type ? source.type : undefined);
  const input: { data: string; name?: string; mimeType?: string } = { data: bytesToBase64(bytes) };
  if (name !== undefined) input.name = name;
  if (mime !== undefined) input.mimeType = mime;
  return input;
}

/** The bytes of a result returned inline (no `path`). Throws if it was written to disk. */
export function outputBytes(output: BytesOutput): Uint8Array {
  if (output.data === undefined) {
    throw new Error(
      output.path !== undefined
        ? `The result was written to ${output.path}; read it from disk instead.`
        : "The result carries no inline data.",
    );
  }
  return base64ToBytes(output.data);
}

export function outputBlob(output: BytesOutput, type?: string): Blob {
  const bytes = outputBytes(output);
  return new Blob([bytes as BlobPart], type ? { type } : undefined);
}
