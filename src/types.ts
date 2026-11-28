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

/** Public TypeScript wire shape for Json in the signature-client facade. */
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

/** Public TypeScript wire shape for BytesOutput in the signature-client facade. */
export interface BytesOutput {
  size: number;
  /** Set when the result was written to disk. */
  path?: string;
  /** Set when the result was returned inline (base64). */
  data?: string;
}

// ─── Shared args ─────────────────────────────────────────────────────────────

/** Public TypeScript wire shape for HistorySource in the signature-client facade. */
export type HistorySource = "gui" | "cli" | "mcp" | "api" | "sdk" | "system";

/** Public TypeScript wire shape for Ctx in the signature-client facade. */
export interface Ctx {
  /** Defaults to the active account. */
  accountId?: string;
  source?: HistorySource;
}

/** Public TypeScript wire shape for VerifyTarget in the signature-client facade. */
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

/** Public TypeScript wire shape for ExpectedSigner in the signature-client facade. */
export interface ExpectedSigner {
  signerId: string;
  edPublicKey: string;
  mlDsaPublicKey: string;
}

/** Public TypeScript wire shape for SignerRef in the signature-client facade. */
export type SignerRef =
  | { contactId: string }
  | { accountId: string }
  | ExpectedSigner;

// ─── Signatures & verification ───────────────────────────────────────────────

/** Public TypeScript wire shape for MajikSignatureJSON in the signature-client facade. */
export interface MajikSignatureJSON extends Json {
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string | null;
}

/** Public TypeScript wire shape for VerificationResult in the signature-client facade. */
export interface VerificationResult extends Json {
  valid: boolean;
  signerId?: string | null;
  contentHash?: string | null;
  timestamp: string;
  contentType?: string | null;
  reason?: string | null;
}

/** Public TypeScript wire shape for VerifyResult in the signature-client facade. */
export interface VerifyResult extends VerificationResult {
  signerLabel?: string;
}

/** Public TypeScript wire shape for MajikTimestamp in the signature-client facade. */
export interface MajikTimestamp extends Json {}
/** Public TypeScript wire shape for MajikTsaRequest in the signature-client facade. */
export interface MajikTsaRequest extends Json {}
/** Public TypeScript wire shape for MajikChainAnchor in the signature-client facade. */
export interface MajikChainAnchor extends Json {
  status?: string;
}

/** Public TypeScript wire shape for SignTextOptions in the signature-client facade. */
export interface SignTextOptions {
  contentType?: string;
  timestamp?: string;
  validUntil?: string;
}

/** Public TypeScript wire shape for SignTextResult in the signature-client facade. */
export interface SignTextResult {
  signature: MajikSignatureJSON;
  /** Base64 `serialize()` form, ready to store or send. */
  serialized: string;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType: string | null;
}

/** Public TypeScript wire shape for SignatureMetadata in the signature-client facade. */
export interface SignatureMetadata {
  signerId: string;
  contentHash: string;
  contentType: string | null;
  timestamp: string;
  version: number;
  isExpired: boolean;
  hasTsa: boolean;
}

/** Public TypeScript wire shape for VerifyTextArgs in the signature-client facade. */
export interface VerifyTextArgs {
  text: string;
  /** Base64 `serialize()` output or a JSON string. */
  signature: string;
  target?: VerifyTarget;
  source?: HistorySource;
}

// ─── File signing ────────────────────────────────────────────────────────────

/** Public TypeScript wire shape for SignFileOptions in the signature-client facade. */
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

/** Public TypeScript wire shape for SignDetachedOptions in the signature-client facade. */
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

/** Public TypeScript wire shape for SignFileArgs in the signature-client facade. */
export interface SignFileArgs {
  input: FileInput;
  output?: OutputTarget;
  options?: SignFileOptions;
  ctx?: Ctx;
}

/** Public TypeScript wire shape for SignDetachedArgs in the signature-client facade. */
export interface SignDetachedArgs {
  input: FileInput;
  /** The `.mjksig` envelope. */
  output?: OutputTarget;
  /** The original with embedded signatures stripped (rarely needed). */
  strippedOutput?: OutputTarget;
  options?: SignDetachedOptions;
  ctx?: Ctx;
}

/** Authoritative SignRoom context issued by the session service. */
export interface SessionSigningContext {
  sessionId: string;
  challengeId: string;
  policyHash: string;
}

/** Immutable SignRoom document-revision entry committed by the signature. */
export interface FileVersion {
  version: number;
  timestamp: string;
  contentHash: string;
  createdBy: string;
  previousVersionHash?: string;
  message?: string;
}

/** Public TypeScript wire shape for SignSessionFileOptions in the signature-client facade. */
export interface SignSessionFileOptions {
  sessionContext: SessionSigningContext;
  contentType?: string;
  timestamp?: string;
  mimeType?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  existingEnvelope?: FileInput;
  fileVersion?: FileVersion;
  priorFile?: FileInput;
  message?: string;
}

/** Public TypeScript wire shape for SignSessionFileArgs in the signature-client facade. */
export interface SignSessionFileArgs {
  input: FileInput;
  options: SignSessionFileOptions;
  ctx?: Ctx;
}

/** Public TypeScript wire shape for SessionSigned in the signature-client facade. */
export interface SessionSigned {
  signature: MajikSignatureJSON;
  handler: string;
  mimeType: string;
}

 
/** Public TypeScript wire shape for SignRoomPublicEncryptionIdentity in the signature-client facade. */
export interface SignRoomPublicEncryptionIdentity {
  fingerprint: string;
  publicKey: string;
  mlKemPublicKey: string;
}

/** Public TypeScript wire shape for SignRoomPublicRecipient in the signature-client facade. */
export interface SignRoomPublicRecipient {
  fingerprint: string;
  publicKey: string;
  mlKemPublicKey: string;
}

/** Public TypeScript wire shape for EncryptSignRoomFileArgs in the signature-client facade. */
export interface EncryptSignRoomFileArgs {
  input: FileInput;
  owner: SignRoomPublicEncryptionIdentity;
  recipients?: SignRoomPublicRecipient[];
  output?: OutputTarget;
}

/** Public TypeScript wire shape for EncryptSignRoomFileResult in the signature-client facade. */
export interface EncryptSignRoomFileResult {
  file: BytesOutput;
  contentHash: string;
  originalName: string;
  contentType: string;
  sizeBytes: number;
}

/** Public TypeScript wire shape for DecryptSignRoomFileArgs in the signature-client facade. */
export interface DecryptSignRoomFileArgs {
  input: FileInput;
  accountId: string;
  expectedOriginalName: string;
  expectedContentType: string;
  expectedSizeBytes: number;
  expectedContentHash: string;
  output?: OutputTarget;
}

/** Public TypeScript wire shape for DecryptSignRoomFileResult in the signature-client facade. */
export interface DecryptSignRoomFileResult {
  file: BytesOutput;
  originalName: string;
  contentType: string;
  sizeBytes: number;
  contentHash: string;
}

/** Public TypeScript wire shape for ResignArgs in the signature-client facade. */
export interface ResignArgs {
  previousSignedFile: FileInput;
  newFile: FileInput;
  output?: OutputTarget;
  options?: SignFileOptions;
  ctx?: Ctx;
}

/** Public TypeScript wire shape for BatchSignFilesArgs in the signature-client facade. */
export interface BatchSignFilesArgs {
  inputs: FileInput[];
  /** Folder that receives `<name>` for every signed file. */
  outputDir: string;
  overwrite?: boolean;
  options?: SignFileOptions;
  ctx?: Ctx;
}

/** Public TypeScript wire shape for SignedFile in the signature-client facade. */
export interface SignedFile {
  file: BytesOutput;
  signature: MajikSignatureJSON;
  handler: string;
  mimeType: string;
}

/** Public TypeScript wire shape for DetachedSigned in the signature-client facade. */
export interface DetachedSigned {
  envelope: BytesOutput;
  stripped?: BytesOutput;
  signature: MajikSignatureJSON;
  handler: string;
  mimeType: string;
}

/** Public TypeScript wire shape for BatchSignOutcome in the signature-client facade. */
export interface BatchSignOutcome {
  name: string;
  ok: boolean;
  output?: BytesOutput;
  error?: string;
}

/** Public TypeScript wire shape for TsaBegin in the signature-client facade. */
export interface TsaBegin {
  /** Hand back to `completeSignFile*WithTsa` together with the TSA's timestamp. */
  token: string;
  /** POST this to the TSA. */
  tsaRequest: MajikTsaRequest;
}

// ─── Verify args & results ───────────────────────────────────────────────────

/** Public TypeScript wire shape for VerifyFileArgs in the signature-client facade. */
export interface VerifyFileArgs {
  input: FileInput;
  target?: VerifyTarget;
  source?: HistorySource;
}

/** Public TypeScript wire shape for VerifyDetachedArgs in the signature-client facade. */
export interface VerifyDetachedArgs {
  input: FileInput;
  envelope: FileInput;
  target?: VerifyTarget;
  source?: HistorySource;
}


/** Read/write settings for native-path streaming operations. */
export interface StreamingFileOptions {
  /**
   * Preferred chunk size in bytes (64 KiB–64 MiB).
   * Omit or set to null to use the current native system recommendation.
   * Allocation failures automatically retry with the recommendation and smaller sizes.
   */
  chunkSize?: number | null;
  /** Disable adaptive fallback after an explicit chunk-size allocation failure. */
  strictChunkSize?: boolean;
  /** Optional maximum size for the source and any prior revision file. */
  maxBytes?: number;
}

/** Privacy-preserving system-resource profile returned by the native plugin. */
export interface SystemProfile {
  totalMemoryBytes: number;
  availableMemoryBytes: number;
  hostAvailableMemoryBytes: number;
  /** False when sysinfo could not initialize; available memory may then come from cgroups. */
  memoryProbeSucceeded: boolean;
  cgroupMemoryLimitBytes: number | null;
  cpuThreads: number;
  architecture: string;
  operatingSystem: string;
}

/** Native resource manager recommendation for one streaming operation. */
export interface RecommendedStreamingConfig {
  chunkSize: number;
  memoryBudgetBytes: number;
  maximumOverrideChunkSize: number;
  automaticMaxChunkSize: number;
  profile: "highPerformance" | "balanced" | "lowMemory";
}

/** Common result for embedded and detached streaming signing. */
export interface StreamingSignResult {
  signature: MajikSignatureJSON;
  output: {
    path: string;
    sizeBytes: number;
  };
  sourceSizeBytes: number;
  handler: string;
  mimeType: string;
}

/** Native-path embedded signing. File bytes never cross the webview IPC boundary. */
export interface StreamingEmbeddedSignArgs {
  operationId: string;
  inputPath: string;
  outputPath: string;
  options?: Omit<SignFileOptions, "priorSignedFile">;
  ctx?: Ctx;
  streaming?: StreamingFileOptions;
  overwrite?: boolean;
}

/** Native-path detached signing; existingEnvelope is separately size-bounded by Rust. */
export interface StreamingDetachedSignArgs {
  operationId: string;
  inputPath: string;
  outputPath: string;
  options?: SignDetachedOptions;
  ctx?: Ctx;
  streaming?: StreamingFileOptions;
  overwrite?: boolean;
}

/** Append an embedded revision using a native path to the previous signed file. */
export interface StreamingEmbeddedRevisionArgs extends StreamingEmbeddedSignArgs {
  priorFilePath: string;
}

/** Append a detached revision using a native path to the previous signed file. */
export interface StreamingDetachedRevisionArgs extends StreamingDetachedSignArgs {
  priorFilePath: string;
}

/** Verify an embedded signature without loading the whole source into webview memory. */
export interface StreamingVerifyArgs {
  operationId: string;
  inputPath: string;
  target?: VerifyTarget;
  source?: HistorySource;
  streaming?: StreamingFileOptions;
}

/** Verify a native file against a native detached envelope path. */
export interface StreamingDetachedVerifyArgs extends StreamingVerifyArgs {
  envelopePath: string;
}

/** Progress payload emitted while a native-path stream operation is running. */
export interface StreamingProgressPayload {
  operationId: string;
  bytesProcessed: number;
  totalBytes: number | null;
  /** One-based streaming attempt; increases when an allocation retry begins. */
  attempt?: number;
  /** Chunk size used by this attempt, in bytes. */
  effectiveChunkSize?: number;
  /** True when this progress belongs to a fallback attempt. */
  adaptiveFallback?: boolean;
  /** Zero-based index of the file currently being processed in a batch. */
  fileIndex?: number;
  /** Number of source files in the batch. */
  totalFiles?: number;
  /** Manifest path of the file currently being processed. */
  path?: string;
}

/** Envelope sent on the dedicated streaming-progress event channel. */
export interface StreamingProgressEvent {
  type: "stream-progress";
  payload: StreamingProgressPayload;
}

/** Public TypeScript wire shape for FileChain in the signature-client facade. */
export interface FileChain {
  latest: VerificationResult;
  history: Json[];
  chainValid: boolean;
}

/** Public TypeScript wire shape for RevisionSet in the signature-client facade. */
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

/** Public TypeScript wire shape for Permit in the signature-client facade. */
export interface Permit {
  permitted: boolean;
  reason: string | null;
}

/** Public TypeScript wire shape for FileSignatureInfo in the signature-client facade. */
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

/** Public TypeScript wire shape for SealedFile in the signature-client facade. */
export interface SealedFile {
  file: BytesOutput;
  sealInfo: Json;
  handler: string;
  mimeType: string;
}

/** Public TypeScript wire shape for SignatoriesFilter in the signature-client facade. */
export type SignatoriesFilter = "signed" | "pending" | "all";

// ─── Maps, batches, order ────────────────────────────────────────────────────

/** Public TypeScript wire shape for BatchDetachedOptions in the signature-client facade. */
export interface BatchDetachedOptions {
  mode?: "map" | "separate";
  contentType?: string;
  timestamp?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  continueOnError?: boolean;
}

/** Public TypeScript wire shape for BatchDetachedArgs in the signature-client facade. */
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

/** Public TypeScript wire shape for Failure in the signature-client facade. */
export interface Failure {
  path: string;
  error: string;
}

/** Public TypeScript wire shape for BatchDetached in the signature-client facade. */
export interface BatchDetached {
  map?: BytesOutput;
  signatures: Array<{ path: string; output: BytesOutput }>;
  failures: Failure[];
}

/** A source file for native-path detached batch signing or MJKSMAP verification. */
export interface StreamingBatchPathInput {
  /** Relative path committed in the MJKSMAP manifest. */
  manifestPath: string;
  /** Native filesystem path opened by Rust; source bytes do not cross IPC. */
  sourcePath: string;
  /** Optional MIME metadata; otherwise inferred from the file name. */
  mimeType?: string;
}

/** Bounded chunking and optional per-file size policy for native batch operations. */
export interface BatchStreamingFileOptions {
  /** Requested native buffer size (64 KiB–64 MiB); defaults to the system recommendation. */
  chunkSize?: number;
  /** Optional per-source-file byte ceiling checked against canonical streamed input. */
  maxBytesPerFile?: number;
  /** Disable adaptive chunk-size fallback after an allocation failure. */
  strictChunkSize?: boolean;
}

/** Detached native batch signing options. */
export interface StreamingBatchSignOptions {
  /** map writes one .mjksmap file; separate writes one .mjksig sidecar per successful file. */
  mode?: "map" | "separate";
  contentType?: string;
  timestamp?: string;
  expectedSigners?: SignerRef[];
  validUntil?: string;
  continueOnError?: boolean;
}

/** Request native detached batch signing without materializing source files in the webview. */
export interface StreamingBatchSignArgs {
  operationId: string;
  inputs: StreamingBatchPathInput[];
  options?: StreamingBatchSignOptions;
  ctx?: Ctx;
  streaming?: BatchStreamingFileOptions;
  /** Required when mode is map (the default). */
  mapOutputPath?: string;
  /** Required when mode is separate; the directory must already exist. */
  outputDir?: string;
  overwrite?: boolean;
}

/** Output metadata for one native-path batch result. */
export interface StreamingBatchOutput {
  path: string;
  sizeBytes: number;
}

/** Result of native detached batch signing. Source-file bytes are never returned over IPC. */
export interface StreamingBatchSignResult {
  mode: "map" | "separate";
  map?: StreamingBatchOutput;
  signatures: Array<{ manifestPath: string; output: StreamingBatchOutput }>;
  failures: Failure[];
}

/**
 * Request native MJKSMAP verification against explicitly trusted signer material.
 *
 * The Rust streaming verifier requires an account, contact or address in target; it does not
 * use the self-reported keys embedded in the signature envelope.
 */
export interface StreamingBatchVerifyArgs {
  operationId: string;
  mapPath: string;
  inputs: StreamingBatchPathInput[];
  target: VerifyTarget;
  requireAllPresent?: boolean;
  source?: HistorySource;
  streaming?: BatchStreamingFileOptions;
}
/** Public TypeScript wire shape for CosignArgs in the signature-client facade. */
export interface CosignArgs {
  map: FileInput;
  files: FileInput[];
  output?: OutputTarget;
  validUntil?: string;
  continueOnError?: boolean;
  ctx?: Ctx;
}

/** Public TypeScript wire shape for Cosign in the signature-client facade. */
export interface Cosign {
  map: BytesOutput;
  failures: Failure[];
}

/** Public TypeScript wire shape for VerifyMapArgs in the signature-client facade. */
export interface VerifyMapArgs {
  map: FileInput;
  files: FileInput[];
  target?: VerifyTarget;
  requireAllPresent?: boolean;
  source?: HistorySource;
}

/** Public TypeScript wire shape for FileVerifyStatus in the signature-client facade. */
export type FileVerifyStatus =
  | "verified"
  | "invalid"
  | "tampered"
  | "not_in_map";

/** Public TypeScript wire shape for MapVerify in the signature-client facade. */
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

/** Public TypeScript wire shape for MapFileInfo in the signature-client facade. */
export interface MapFileInfo {
  path: string;
  contentHash: string;
  size: number | null;
  mimeType: string | null;
  info: Json;
}

/** Public TypeScript wire shape for OrderArgs in the signature-client facade. */
export interface OrderArgs {
  input: FileInput;
  /** Set for a detached order check. */
  envelope?: FileInput;
  expected: SignerRef[];
  strict?: boolean;
  source?: HistorySource;
}

/** Public TypeScript wire shape for MapOrder in the signature-client facade. */
export interface MapOrder {
  path: string;
  resolveStatus: string;
  order: Json | null;
  reason: string | null;
}

// ─── Stamps ──────────────────────────────────────────────────────────────────

/** Public TypeScript wire shape for StampAssetKind in the signature-client facade. */
export type StampAssetKind = "image" | "audio" | "video" | "text";

/** Public TypeScript wire shape for StampMeta in the signature-client facade. */
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

/** Public TypeScript wire shape for CreateStampArgs in the signature-client facade. */
export interface CreateStampArgs {
  input: FileInput;
  kind: StampAssetKind;
  name: string;
  mimeType?: string;
  accountId?: string;
}

/** Public TypeScript wire shape for SkippedItem in the signature-client facade. */
export interface SkippedItem {
  id: string;
  reason: string;
}

// ─── Contacts & groups ───────────────────────────────────────────────────────

/** Public TypeScript wire shape for SerializedMajikContactGroup in the signature-client facade. */
export interface SerializedMajikContactGroup extends Json {
  id: string;
  isSystem: boolean;
  memberIds: string[];
}

/** Public TypeScript wire shape for ApiResponse in the signature-client facade. */
export interface ApiResponse {
  success: boolean;
  message: string;
}

/** Public TypeScript wire shape for CreateGroupArgs in the signature-client facade. */
export interface CreateGroupArgs {
  id: string;
  name: string;
  meta?: Json;
  initialMemberIds?: string[];
}

/** Public TypeScript wire shape for UpdateGroupMetaArgs in the signature-client facade. */
export interface UpdateGroupMetaArgs {
  id: string;
  name?: string;
  description?: string;
  color?: string;
}

// ─── Logs & preferences ──────────────────────────────────────────────────────

/** Public TypeScript wire shape for HistoryLog in the signature-client facade. */
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

/** Public TypeScript wire shape for UserActivityLog in the signature-client facade. */
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

/** Public TypeScript wire shape for BackupType in the signature-client facade. */
export type BackupType = "stamps" | "contacts" | "appData" | "unknown";

/** Public TypeScript wire shape for AppDataSummary in the signature-client facade. */
export interface AppDataSummary {
  contacts: SerializedMajikContact[];
  groups: SerializedMajikContactGroup[];
  stamps: StampMeta[];
  preferences: UserAppPreferences | null;
}

/** Public TypeScript wire shape for SelectiveRestoreOptions in the signature-client facade. */
export interface SelectiveRestoreOptions {
  stamps?: boolean;
  contacts?: boolean;
  groups?: boolean;
  preferences?: boolean;
  overwriteContacts?: boolean;
}

// ─── Hydration & events ──────────────────────────────────────────────────────

/** Public TypeScript wire shape for SigHydrateReport in the signature-client facade. */
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

/** Public TypeScript wire shape for SigOnlyEventType in the signature-client facade. */
export type SigOnlyEventType = keyof SigOnlyEventMap;
