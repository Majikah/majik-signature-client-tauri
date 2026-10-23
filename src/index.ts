export {
  MajikSignatureClientTauri,
  SIGNATURE_EVENT_CHANNEL,
  SIGNATURE_PLUGIN,
  type MajikSignatureClientTauriOptions,
} from "./client.js";
export {
  base64ToBytes,
  bytesToBase64,
  outputBlob,
  outputBytes,
  toFileInput,
} from "./helpers.js";
export type * from "./types.js";
// The key client's API (accounts, errors, transport) is re-exported for convenience.
export {
  MajikKeyClientError,
  isUnlockRequired,
  type ClientErrorKind,
  type Transport,
} from "@majikah/majik-key-client-tauri";
