/**
 * Wire types for the signature plugin (camelCase JSON). They mirror `majik_signature_client::ipc`.
 * Results that are rich crate-native structures (envelope info, seal info, order results, ...) are
 * typed loosely as `Json`; the fields you rely on are documented where they are used.
 */

import type {
  MajikContactMeta,
  MajikKeyJson,
  SerializedMajikContact,
} from "@majikah/majik-key-client-tauri";

export type { MajikContactMeta, MajikKeyJson, SerializedMajikContact };

export type Json = { [key: string]: unknown };

// ─── Files ───────────────────────────────────────────────────────────────────

/**
 * A file argument. Prefer `{ path }` (Rust reads and validates the file; nothing large crosses
 * IPC). Use `{ data }` (standard base64) only for small in-memory blobs.
 */
export type FileInput =
  | { path: string; mimeType?: string }
  | { data: string; name?: string; mimeType?: string };

/** Where a result goes. Omit `path` to receive the bytes inline as base64. */
export interface OutputTarget {
  path?: string;
  /** Replace an existing file (default: reject with `fileExists`). */
  overwrite?: boolean;
}

export interface BytesOutput {
  size: number;
  /** Set when the result was written to disk. */
  path?: string;
  /** Set when the result was returned inline (base64). */
  data?: string;
}

// ─── Shared args ─────────────────────────────────────────────────────────────

export type HistorySource = "gui" | "cli" | "mcp" | "api" | "sdk" | "system";

export interface Ctx {
  /** Defaults to the active account. */
  accountId?: string;
  source?: HistorySource;
}

export interface VerifyTarget {
  contactId?: string;
  /** Base64 X25519 public key of a known contact. */
  address?: string;
  /** One of your own accounts. */
  accountId?: string;
  expectedSignerId?: string;
  mimeType?: string;
  /** ISO timestamp to verify "as of". */
  now?: string;
}

export interface ExpectedSigner {
  signerId: string;
  edPublicKey: string;
  mlDsaPublicKey: string;
}

export type SignerRef =
  | { contactId: string }
  | { accountId: string }
  | ExpectedSigner;

// ─── Signatures & verification ───────────────────────────────────────────────

export interface MajikSignatureJSON extends Json {
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string | null;
}

export interface VerificationResult extends Json {
  valid: boolean;
  signerId?: string | null;
  contentHash?: string | null;
  timestamp: string;
  contentType?: string | null;
  reason?: string | null;
}

export interface VerifyResult extends VerificationResult {
  signerLabel?: string;
}

export interface MajikTimestamp extends Json {}
export interface MajikTsaRequest extends Json {}
export interface MajikChainAnchor extends Json {
  status?: string;
}

export interface SignTextOptions {
  contentType?: string;
  timestamp?: string;
  validUntil?: string;
}

export interface SignTextResult {
  signature: MajikSignatureJSON;
  /** Base64 `serialize()` form, ready to store or send. */
  serialized: string;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType: string | null;
}

export interface SignatureMetadata {
  signerId: string;
  contentHash: string;
  contentType: string | null;
  timestamp: string;
  version: number;
  isExpired: boolean;
  hasTsa: boolean;
}

export interface VerifyTextArgs {
  text: string;
  /** Base64 `serialize()` output or a JSON string. */
  signature: string;
  target?: VerifyTarget;
  source?: HistorySource;
}

// ─── File signing ────────────────────────────────────────────────────────────

export interface SignFileOptions {
  contentType?: string;
  timestamp?: string;
  mimeType?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  priorSignedFile?: FileInput;
  message?: string;
  /** Keep an encrypted copy of the output in the history (default true). */
  saveHistory?: boolean;
}

export interface SignDetachedOptions {
  contentType?: string;
  timestamp?: string;
  mimeType?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  /** An existing `.mjksig` to co-sign. */
  existingEnvelope?: FileInput;
  tsa?: MajikTimestamp;
  saveHistory?: boolean;
}

export interface SignFileArgs {
  input: FileInput;
  output?: OutputTarget;
  options?: SignFileOptions;
  ctx?: Ctx;
}

export interface SignDetachedArgs {
  input: FileInput;
  /** The `.mjksig` envelope. */
  output?: OutputTarget;
  /** The original with embedded signatures stripped (rarely needed). */
  strippedOutput?: OutputTarget;
  options?: SignDetachedOptions;
  ctx?: Ctx;
}

export interface ResignArgs {
  previousSignedFile: FileInput;
  newFile: FileInput;
  output?: OutputTarget;
  options?: SignFileOptions;
  ctx?: Ctx;
}

export interface BatchSignFilesArgs {
  inputs: FileInput[];
  /** Folder that receives `<name>` for every signed file. */
  outputDir: string;
  overwrite?: boolean;
  options?: SignFileOptions;
  ctx?: Ctx;
}

export interface SignedFile {
  file: BytesOutput;
  signature: MajikSignatureJSON;
  handler: string;
  mimeType: string;
}

export interface DetachedSigned {
  envelope: BytesOutput;
  stripped?: BytesOutput;
  signature: MajikSignatureJSON;
  handler: string;
  mimeType: string;
}

export interface BatchSignOutcome {
  name: string;
  ok: boolean;
  output?: BytesOutput;
  error?: string;
}

export interface TsaBegin {
  /** Hand back to `completeSignFile*WithTsa` together with the TSA's timestamp. */
  token: string;
  /** POST this to the TSA. */
  tsaRequest: MajikTsaRequest;
}

// ─── Verify args & results ───────────────────────────────────────────────────

export interface VerifyFileArgs {
  input: FileInput;
  target?: VerifyTarget;
  source?: HistorySource;
}

export interface VerifyDetachedArgs {
  input: FileInput;
  envelope: FileInput;
  target?: VerifyTarget;
  source?: HistorySource;
}

export interface FileChain {
  latest: VerificationResult;
  history: Json[];
  chainValid: boolean;
}

export interface RevisionSet {
  allValid: boolean;
  isCompleteSet: boolean;
  results: Array<{
    version: number;
    status: string;
    signerId: string | null;
    reason: string | null;
  }>;
}

export interface Permit {
  permitted: boolean;
  reason: string | null;
}

export interface FileSignatureInfo {
  isSigned: boolean;
  signatures: Array<{
    signerId: string;
    signerLabel: string;
    contentHash: string;
    timestamp: string;
    hasTsa: boolean;
    isExpired: boolean;
  }>;
  envelope: Json | null;
}

export interface SealedFile {
  file: BytesOutput;
  sealInfo: Json;
  handler: string;
  mimeType: string;
}

export type SignatoriesFilter = "signed" | "pending" | "all";

// ─── Maps, batches, order ────────────────────────────────────────────────────

export interface BatchDetachedOptions {
  mode?: "map" | "separate";
  contentType?: string;
  timestamp?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  continueOnError?: boolean;
}

export interface BatchDetachedArgs {
  inputs: FileInput[];
  /** Map mode: where the `.mjksmap` goes. */
  mapOutput?: OutputTarget;
  /** Separate mode: folder for the `<name>.mjksig` files. */
  outputDir?: string;
  overwrite?: boolean;
  options?: BatchDetachedOptions;
  ctx?: Ctx;
}

export interface Failure {
  path: string;
  error: string;
}

export interface BatchDetached {
  map?: BytesOutput;
  signatures: Array<{ path: string; output: BytesOutput }>;
  failures: Failure[];
}

export interface CosignArgs {
  map: FileInput;
  files: FileInput[];
  output?: OutputTarget;
  validUntil?: string;
  continueOnError?: boolean;
  ctx?: Ctx;
}

export interface Cosign {
  map: BytesOutput;
  failures: Failure[];
}

export interface VerifyMapArgs {
  map: FileInput;
  files: FileInput[];
  target?: VerifyTarget;
  requireAllPresent?: boolean;
  source?: HistorySource;
}

export type FileVerifyStatus =
  | "verified"
  | "invalid"
  | "tampered"
  | "not_in_map";

export interface MapVerify {
  results: Array<{
    path: string;
    status: FileVerifyStatus;
    results: VerificationResult[] | null;
    reason: string | null;
    relocatedFrom: string | null;
  }>;
  summary: {
    total: number;
    verified: number;
    invalid: number;
    tampered: number;
    notInMap: number;
    allValid: boolean;
  };
  missingFromBatch: string[];
}

export interface MapFileInfo {
  path: string;
  contentHash: string;
  size: number | null;
  mimeType: string | null;
  info: Json;
}

export interface OrderArgs {
  input: FileInput;
  /** Set for a detached order check. */
  envelope?: FileInput;
  expected: SignerRef[];
  strict?: boolean;
  source?: HistorySource;
}

export interface MapOrder {
  path: string;
  resolveStatus: string;
  order: Json | null;
  reason: string | null;
}

// ─── Stamps ──────────────────────────────────────────────────────────────────

export type StampAssetKind = "image" | "audio" | "video" | "text";

export interface StampMeta {
  id: string;
  kind: StampAssetKind;
  name: string;
  mimeType: string | null;
  sizeBytes: number;
  fingerprint: string;
  timestamp: string;
  lastUpdate: string;
}

export interface CreateStampArgs {
  input: FileInput;
  kind: StampAssetKind;
  name: string;
  mimeType?: string;
  accountId?: string;
}

export interface SkippedItem {
  id: string;
  reason: string;
}

// ─── Contacts & groups ───────────────────────────────────────────────────────

export interface SerializedMajikContactGroup extends Json {
  id: string;
  isSystem: boolean;
  memberIds: string[];
}

export interface ApiResponse {
  success: boolean;
  message: string;
}

export interface CreateGroupArgs {
  id: string;
  name: string;
  meta?: Json;
  initialMemberIds?: string[];
}

export interface UpdateGroupMetaArgs {
  id: string;
  name?: string;
  description?: string;
  color?: string;
}

// ─── Logs & preferences ──────────────────────────────────────────────────────

export interface HistoryLog extends Json {
  id: string;
  reference_id: string;
  timestamp: string;
  fingerprint?: string;
  historyType: "sign" | "verify" | "seal" | "notarize";
  status: "success" | "failed" | "cancelled" | "pending";
  source: HistorySource;
  operation: {
    digest: string;
    detached: boolean;
    sealed: boolean;
    tsa: boolean;
  };
  valid?: boolean;
}

export interface UserActivityLog extends Json {
  id: string;
  reference_id: string;
  timestamp: string;
  fingerprint?: string;
  action: string;
  metadata?: Json;
}

/** Tri-state leaves (absent / false / true) exactly as stored; see `UserAppPreferences` in Rust. */
export type UserAppPreferences = Json;

// ─── Backups ─────────────────────────────────────────────────────────────────

export type BackupType = "stamps" | "contacts" | "appData" | "unknown";

export interface AppDataSummary {
  contacts: SerializedMajikContact[];
  groups: SerializedMajikContactGroup[];
  stamps: StampMeta[];
  preferences: UserAppPreferences | null;
}

export interface SelectiveRestoreOptions {
  stamps?: boolean;
  contacts?: boolean;
  groups?: boolean;
  preferences?: boolean;
  overwriteContacts?: boolean;
}

// ─── Hydration & events ──────────────────────────────────────────────────────

export interface SigHydrateReport {
  contacts: { contactsLoaded: number; contactsSkipped: SkippedItem[] };
  historySkipped: SkippedItem[];
  activitySkipped: SkippedItem[];
  stampsSkipped: SkippedItem[];
  keys: {
    keysLoaded: number;
    keysSkipped: SkippedItem[];
    accountsFailed: SkippedItem[];
  };
}

/** Events emitted by the signature client in addition to the key client's. */
export interface SigOnlyEventMap {
  sign: Json;
  verify: VerifyResult;
  "new-stamp": StampMeta;
  "removed-stamp": string;
  "new-contact": SerializedMajikContact;
  "new-contact-group": SerializedMajikContactGroup;
  "removed-contact": string;
  "removed-contact-group": SerializedMajikContactGroup;
  "contact-group-change": SerializedMajikContactGroup;
  "history-log": HistoryLog;
  "activity-log": UserActivityLog;
}

export type SigOnlyEventType = keyof SigOnlyEventMap;
