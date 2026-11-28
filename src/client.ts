/**
 * Typed client facade for the native Majik Signature Tauri plugin.
 * Command payload validation here is preflight only; Rust remains authoritative.
 */
import {
  MajikKeyClientTauri,
  type MajikKeyClientTauriOptions,
  type MajikContactMeta,
  type OpenedSession,
} from "@majikah/majik-key-client-tauri";

import type {
  ApiResponse,
  AppDataSummary,
  BackupType,
  BatchDetached,
  BatchDetachedArgs,
  BatchSignFilesArgs,
  BatchStreamingFileOptions,
  StreamingBatchSignArgs,
  StreamingBatchSignResult,
  StreamingBatchVerifyArgs,
  StreamingBatchPathInput,
  BatchSignOutcome,
  BytesOutput,
  Cosign,
  CosignArgs,
  CreateGroupArgs,
  CreateStampArgs,
  Ctx,
  DetachedSigned,
  ExpectedSigner,
  FileChain,
  FileInput,
  FileSignatureInfo,
  HistoryLog,
  HistorySource,
  Json,
  MajikChainAnchor,
  MajikSignatureJSON,
  MajikTimestamp,
  MapFileInfo,
  MapOrder,
  MapVerify,
  OrderArgs,
  OutputTarget,
  Permit,
  ResignArgs,
  RevisionSet,
  SealedFile,
  SelectiveRestoreOptions,
  SerializedMajikContact,
  SerializedMajikContactGroup,
  SigHydrateReport,
  SigOnlyEventMap,
  SigOnlyEventType,
  SignatoriesFilter,
  SignatureMetadata,
  SignDetachedArgs,
  SignSessionFileArgs,
  SessionSigned,
  EncryptSignRoomFileArgs,
  EncryptSignRoomFileResult,
  DecryptSignRoomFileArgs,
  DecryptSignRoomFileResult,
  SignedFile,
  SignerRef,
  SignFileArgs,
  StreamingDetachedRevisionArgs,
  StreamingDetachedSignArgs,
  StreamingDetachedVerifyArgs,
  StreamingEmbeddedRevisionArgs,
  StreamingEmbeddedSignArgs,
  StreamingFileOptions,
  SystemProfile,
  RecommendedStreamingConfig,
  StreamingProgressEvent,
  StreamingProgressPayload,
  StreamingSignResult,
  StreamingVerifyArgs,
  SignTextOptions,
  SignTextResult,
  SkippedItem,
  StampAssetKind,
  StampMeta,
  TsaBegin,
  UpdateGroupMetaArgs,
  UserActivityLog,
  UserAppPreferences,
  VerifyDetachedArgs,
  VerifyFileArgs,
  VerifyMapArgs,
  VerifyResult,
  VerifyTarget,
  VerifyTextArgs,
} from "./types.js";

/** Registered Tauri plugin name used by command invocations. */
export const SIGNATURE_PLUGIN = "majik-signature-client";
/** Combined key-client and signature-client state event channel. */
export const SIGNATURE_EVENT_CHANNEL = "majik-signature-client:event";
/** Dedicated progress channel; events do not refresh the signature read-model. */
export const SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL =
  "majik-signature-client:stream-progress";

export type MajikSignatureClientTauriOptions = MajikKeyClientTauriOptions;

/** Drop `undefined` values: serde treats a missing key differently from an explicit `null`. */
function compact(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  );
}


const MIN_STREAM_CHUNK_SIZE = 64 * 1024;
const MAX_STREAM_CHUNK_SIZE = 64 * 1024 * 1024;
const MAX_STREAM_OPERATION_ID_CHARS = 128;
const MAX_NATIVE_PATH_CHARS = 4_096;
const MAX_BATCH_FILES = 10_000;
const MAX_BATCH_METADATA_BYTES = 8 * 1024 * 1024;
const MAX_EXPECTED_SIGNERS = 1_000;
const UNSAFE_INPUT_CHARACTERS = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u;

/** Reject oversized or control-bearing strings before IPC serialization. */
function validateBoundedText(value: string, field: string, maximum: number): void {
  if (value.length > maximum || UNSAFE_INPUT_CHARACTERS.test(value)) {
    throw new TypeError(field + " must be at most " + maximum +
      " UTF-16 code units and contain no control or bidi override characters.");
  }
}

/** Validate a caller-supplied native path without imposing a filesystem sandbox. */
function validateNativePath(path: string, field: string): void {
  if (path.trim().length === 0) throw new TypeError(field + " must not be empty.");
/** Invoke the native validate_bounded_text operation. */
  validateBoundedText(path, field, MAX_NATIVE_PATH_CHARS);
}

/** Keep stream correlation IDs small and safe for the native active-operation registry. */
function validateOperationId(operationId: string): void {
  if (
    operationId.length === 0 ||
    operationId.length > MAX_STREAM_OPERATION_ID_CHARS ||
    !/^[A-Za-z0-9._:-]+$/u.test(operationId)
  ) {
    throw new TypeError("operationId must contain 1–128 restricted ASCII characters.");
  }
}

function validateStreamingOptions(options?: StreamingFileOptions): void {
  const chunkSize = options?.chunkSize;
  if (
    chunkSize !== undefined &&
    chunkSize !== null &&
    (!Number.isSafeInteger(chunkSize) ||
      chunkSize < MIN_STREAM_CHUNK_SIZE ||
      chunkSize > MAX_STREAM_CHUNK_SIZE)
  ) {
    throw new RangeError(
      "chunkSize must be between " + MIN_STREAM_CHUNK_SIZE + " and " +
      MAX_STREAM_CHUNK_SIZE + " bytes.",
    );
  }
  const maxBytes = options?.maxBytes;
  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 0)) {
    throw new RangeError("maxBytes must be a non-negative safe integer.");
  }
}

function validateBatchStreamingOptions(options?: BatchStreamingFileOptions): void {
  const chunkSize = options?.chunkSize;
  if (
    chunkSize !== undefined &&
    (!Number.isSafeInteger(chunkSize) ||
      chunkSize < MIN_STREAM_CHUNK_SIZE ||
      chunkSize > MAX_STREAM_CHUNK_SIZE)
  ) {
    throw new RangeError(
      "chunkSize must be between " + MIN_STREAM_CHUNK_SIZE + " and " +
      MAX_STREAM_CHUNK_SIZE + " bytes.",
    );
  }
  const maxBytes = options?.maxBytesPerFile;
  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 0)) {
    throw new RangeError("maxBytesPerFile must be a non-negative safe integer.");
  }
}

/** Mirror the core manifest alias rules before checking duplicate entries. */
function normalizeManifestPath(path: string): string {
/** Invoke the native validate_bounded_text operation. */
  validateBoundedText(path, "manifestPath", MAX_NATIVE_PATH_CHARS);
  let normalized = path.replace(/\\/gu, "/").trim();
  if (/^[A-Za-z]:/u.test(normalized)) normalized = normalized.slice(2);
  normalized = normalized.replace(/^\/+/u, "");
  if (
    normalized.length === 0 ||
    normalized.split("/").some((segment) => segment === "..")
  ) {
    throw new TypeError("manifestPath must normalize to a non-traversing relative path.");
  }
  return normalized;
}

function validateStreamingBatchInputs(inputs: StreamingBatchPathInput[]): void {
  if (inputs.length === 0 || inputs.length > MAX_BATCH_FILES) {
    throw new RangeError("inputs must contain between 1 and " + MAX_BATCH_FILES + " files.");
  }
  const seen = new Set<string>();
  let metadataBytes = 0;
  const encoder = new TextEncoder();
  for (const input of inputs) {
    const manifestPath = normalizeManifestPath(input.manifestPath);
    validateNativePath(input.sourcePath, "sourcePath");
    if (input.mimeType !== undefined) validateBoundedText(input.mimeType, "mimeType", 1_024);
    if (seen.has(manifestPath)) {
      throw new TypeError("Duplicate manifestPath after normalization: " + manifestPath);
    }
    seen.add(manifestPath);
    metadataBytes +=
      encoder.encode(input.manifestPath).byteLength +
      encoder.encode(input.sourcePath).byteLength +
      (input.mimeType === undefined ? 0 : encoder.encode(input.mimeType).byteLength);
    if (metadataBytes > MAX_BATCH_METADATA_BYTES) {
      throw new RangeError("Batch path and MIME metadata exceeds the 8 MiB request limit.");
    }
  }
}

function validateExpectedSigners(signers?: SignerRef[]): void {
  if (!signers) return;
  if (signers.length > MAX_EXPECTED_SIGNERS) {
    throw new RangeError("expectedSigners cannot exceed " + MAX_EXPECTED_SIGNERS + " entries.");
  }
  for (const signer of signers) {
    if ("contactId" in signer) {
      validateBoundedText(signer.contactId, "expectedSigners.contactId", 256);
    } else if ("accountId" in signer) {
      validateBoundedText(signer.accountId, "expectedSigners.accountId", 256);
    } else {
      validateBoundedText(signer.signerId, "expectedSigners.signerId", 256);
      validateBoundedText(signer.edPublicKey, "expectedSigners.edPublicKey", 1_024);
      validateBoundedText(signer.mlDsaPublicKey, "expectedSigners.mlDsaPublicKey", 8_192);
    }
  }
}

function validateSigningMetadata(options?: StreamingBatchSignArgs["options"]): void {
  if (!options) return;
  if (options.contentType !== undefined) validateBoundedText(options.contentType, "contentType", 1_024);
  if (options.timestamp !== undefined) validateBoundedText(options.timestamp, "timestamp", 128);
  if (options.validUntil !== undefined) validateBoundedText(options.validUntil, "validUntil", 128);
/** Invoke the native validate_expected_signers operation. */
  validateExpectedSigners(options.expectedSigners);
}

function validateFileInputMetadata(input: FileInput, field: string): void {
  if ("path" in input) {
    validateNativePath(input.path, field);
  } else {
    const maximumEncodedLength = Math.ceil((16 * 1024 * 1024) / 3) * 4;
    if (input.data.trim().length > maximumEncodedLength) {
      throw new RangeError(field + " exceeds the 16 MiB inline envelope limit.");
    }
    if (input.name !== undefined) validateBoundedText(input.name, "fileName", MAX_NATIVE_PATH_CHARS);
  }
  if (input.mimeType !== undefined) validateBoundedText(input.mimeType, "mimeType", 1_024);
}

function validateStreamingSignArgs(
  args: StreamingEmbeddedSignArgs | StreamingDetachedSignArgs,
  priorFilePath?: string,
): void {
/** Invoke the native validate_operation_id operation. */
  validateOperationId(args.operationId);
/** Invoke the native validate_native_path operation. */
  validateNativePath(args.inputPath, "inputPath");
/** Invoke the native validate_native_path operation. */
  validateNativePath(args.outputPath, "outputPath");
/** Invoke the native validate_streaming_options operation. */
  validateStreamingOptions(args.streaming);
  if (priorFilePath !== undefined) validateNativePath(priorFilePath, "priorFilePath");
  if (args.ctx?.accountId !== undefined) validateBoundedText(args.ctx.accountId, "accountId", 256);
/** Invoke the native validate_expected_signers operation. */
  validateExpectedSigners(args.options?.expectedSigners);
  if (args.options?.contentType !== undefined) validateBoundedText(args.options.contentType, "contentType", 1_024);
  if (args.options?.timestamp !== undefined) validateBoundedText(args.options.timestamp, "timestamp", 128);
  if (args.options?.mimeType !== undefined) validateBoundedText(args.options.mimeType, "mimeType", 1_024);
  if (args.options?.validUntil !== undefined) validateBoundedText(args.options.validUntil, "validUntil", 128);
  if (args.options && "message" in args.options && args.options.message !== undefined) {
    validateBoundedText(args.options.message, "message", 4_096);
  }
  if (args.options && "existingEnvelope" in args.options && args.options.existingEnvelope) {
    validateFileInputMetadata(args.options.existingEnvelope, "existingEnvelope");
  }
}

function validateVerificationTarget(target?: VerifyTarget, requireTrusted = false): void {
  if (target?.accountId !== undefined) validateBoundedText(target.accountId, "accountId", 256);
  if (target?.contactId !== undefined) validateBoundedText(target.contactId, "contactId", 256);
  if (target?.address !== undefined) validateBoundedText(target.address, "address", 4_096);
  if (target?.expectedSignerId !== undefined) validateBoundedText(target.expectedSignerId, "expectedSignerId", 256);
  if (target?.mimeType !== undefined) validateBoundedText(target.mimeType, "mimeType", 1_024);
  if (target?.now !== undefined) validateBoundedText(target.now, "now", 128);
  if (requireTrusted && !target?.accountId && !target?.contactId && !target?.address) {
    throw new TypeError(
      "Streaming MJKSMAP verification requires a trusted accountId, contactId or address.",
    );
  }
}


type AnyOn = (type: string, listener: (payload: unknown) => void) => () => void;

/**
 * TypeScript facade over `tauri-plugin-majik-signature-client`.
 *
 * It extends the key client facade (accounts, lock/unlock, passphrases, the read-model and its
 * events all work exactly as there) and adds contacts, groups, stamps, logs, preferences,
 * signing and verification, seals, signature maps and backups. Every key, stamp and signature
 * operation runs in Rust.
 *
 * **Files:** pass `{ path }` (Rust reads and validates the file) rather than bytes. Results are
 * written to `output.path`, or returned inline as base64 when no path is given
 * (see `outputBytes()` / `outputBlob()`).
 *
 * Subclass this for the online features (see `MajikSignatureClientDatabase`): use `this.invoke()`
 * for further commands and `this.getUser()`-style state of your own.
 */
export class MajikSignatureClientTauri extends MajikKeyClientTauri {
  /** Set by `open()` when this call hydrated the Rust client (null if it was already open). */
  lastSigHydrateReport: SigHydrateReport | null = null;

  private unlistenStreamProgress: (() => void) | null = null;
  private readonly streamProgressListeners = new Set<
    (payload: StreamingProgressPayload) => void
  >();

/** Create the typed facade using the supplied native transport or the default Tauri transport. */
  constructor(options: MajikSignatureClientTauriOptions = {}) {
    super({
      plugin: SIGNATURE_PLUGIN,
      eventChannel: SIGNATURE_EVENT_CHANNEL,
      ...options,
    });
  }

/** Attach the dedicated streaming progress listener and initialize the native session. */
  protected override async initialize(): Promise<OpenedSession> {
    // Progress events use a dedicated channel so they never trigger snapshot refreshes
    // in the inherited key-client event pipeline.
    this.unlistenStreamProgress = await this.transport.listen<StreamingProgressEvent>(
      SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL,
      (event) => {
        if (event.type !== "stream-progress") return;
        for (const listener of [...this.streamProgressListeners]) {
          try {
            listener(event.payload);
          } catch (error) {
            console.error("[majik-signature-client] stream progress listener threw", error);
          }
        }
      },
    );

    try {
      const opened = await super.initialize();
      this.lastSigHydrateReport =
        opened.report as unknown as SigHydrateReport | null;
      return opened;
    } catch (error) {
      this.unlistenStreamProgress?.();
      this.unlistenStreamProgress = null;
      throw error;
    }
  }

  /** Subscribe to native streaming progress without refreshing the signature read-model. */
/** Subscribe to native streaming progress without refreshing the signature read-model. */
  onStreamProgress(
    listener: (payload: StreamingProgressPayload) => void,
  ): () => void {
    this.streamProgressListeners.add(listener);
    return () => this.streamProgressListeners.delete(listener);
  }

  /** Stop progress notifications before disposing the inherited key/signature session. */
/** Release progress subscriptions and dispose the inherited key-client session. */
  override async dispose(): Promise<void> {
    this.unlistenStreamProgress?.();
    this.unlistenStreamProgress = null;
    this.streamProgressListeners.clear();
    await super.dispose();
  }

  /** Build the current Rust snapshot without rehydrating storage. */
/** Invoke the native snapshot_signature_client operation. */
  snapshotSignatureClient(): Promise<unknown> {
    return this.invoke<unknown>("snapshot");
  }

  /** Open the signature session and hydrate the Rust client if needed. */
/** Invoke the native open_signature_session operation. */
  openSignatureSession(): Promise<OpenedSession> {
    return this.invoke<OpenedSession>("open_session");
  }

  /** Reload contacts, logs, stamps and keys from storage without clobbering the key client setup. */
/** Invoke the native hydrate_signature_client operation. */
  hydrateSignatureClient(): Promise<SigHydrateReport> {
    return this.invoke<SigHydrateReport>("hydrate");
  }

  /** Reset managed signature data while preserving audit history. */
/** Invoke the native reset_data operation. */
  resetData(): Promise<void> {
    return this.invoke<void>("reset_data");
  }

  /** Subscribe to the signature client's own events (`sign`, `new-stamp`, `new-contact`, ...). */
  onSig<K extends SigOnlyEventType>(
    type: K,
    listener: (payload: SigOnlyEventMap[K]) => void,
  ): () => void {
    const on = (this as unknown as { on: AnyOn }).on.bind(this);
    return on(type, listener as (payload: unknown) => void);
  }

  /**
   * Run `fn` with the account unlocked for the whole callback, however many signing operations it
   * performs. The account is re-locked afterwards (unless one-time unlock is on), even if `fn`
   * throws.
   */
  async withSigningSession<T>(
    accountId: string | undefined,
    fn: () => Promise<T>,
  ): Promise<T> {
    await this.beginSigningSession(accountId);
    try {
      return await fn();
    } finally {
      await this.endSigningSession();
    }
  }

  /** Rename an account and keep its contact in the directory in sync. */
/** Invoke the native update_account_label operation. */
  override updateAccountLabel(id: string, label: string): Promise<void> {
    return super.updateAccountLabel(id, label);
  }

  /** Update an own account's contact meta (a non-empty label also renames the key). */
/** Invoke the native update_own_account_meta operation. */
  updateOwnAccountMeta(id: string, meta: MajikContactMeta): Promise<void> {
    return this.invoke<void>("update_own_account_meta", compact({ id, meta }));
  }

/** Invoke the native get_user_app_preferences operation. */
  getUserAppPreferences(): Promise<UserAppPreferences> {
    return this.invoke<UserAppPreferences>("get_user_app_preferences");
  }

/** Invoke the native set_user_app_preferences operation. */
  setUserAppPreferences(preferences: UserAppPreferences): Promise<void> {
    return this.invoke<void>(
      "set_user_app_preferences",
      compact({ preferences }),
    );
  }

/** Invoke the native reset_user_app_preferences operation. */
  resetUserAppPreferences(): Promise<void> {
    return this.invoke<void>("reset_user_app_preferences");
  }

  /** History entries of the active account. */
/** Invoke the native list_history_logs operation. */
  listHistoryLogs(): Promise<HistoryLog[]> {
    return this.invoke<HistoryLog[]>("list_history_logs");
  }

  /** Audit entries of the active account. */
/** Invoke the native list_activity_logs operation. */
  listActivityLogs(): Promise<UserActivityLog[]> {
    return this.invoke<UserActivityLog[]>("list_activity_logs");
  }

/** Invoke the native clear_history_logs operation. */
  clearHistoryLogs(): Promise<void> {
    return this.invoke<void>("clear_history_logs");
  }

/** Invoke the native clear_activity_logs operation. */
  clearActivityLogs(): Promise<void> {
    return this.invoke<void>("clear_activity_logs");
  }

  /** Clear both logs for the active account and leave a restart audit entry. */
/** Invoke the native restart_logs operation. */
  restartLogs(): Promise<void> {
    return this.invoke<void>("restart_logs");
  }

/** Invoke the native hydrate_logs operation. */
  hydrateLogs(): Promise<void> {
    return this.invoke<void>("hydrate_logs");
  }

  /** Own-account label, else contact label, else a shortened id. */
/** Invoke the native resolve_signer_label operation. */
  resolveSignerLabel(signerId: string): Promise<string> {
    return this.invoke<string>("resolve_signer_label", compact({ signerId }));
  }

  /** Unlock once for several signing operations; pair with `endSigningSession()`. */
/** Invoke the native begin_signing_session operation. */
  beginSigningSession(accountId?: string): Promise<void> {
    return this.invoke<void>("begin_signing_session", compact({ accountId }));
  }

/** Invoke the native end_signing_session operation. */
  endSigningSession(): Promise<void> {
    return this.invoke<void>("end_signing_session");
  }

/** Invoke the native force_end_signing_session operation. */
  forceEndSigningSession(): Promise<void> {
    return this.invoke<void>("force_end_signing_session");
  }

/** Invoke the native is_signing_session_active operation. */
  isSigningSessionActive(): Promise<boolean> {
    return this.invoke<boolean>("is_signing_session_active");
  }

  /** Resolve the account's domain-separated Majik Key Solana signer address. */
/** Invoke the native get_solana_signer_address operation. */
  getSolanaSignerAddress(accountId?: string): Promise<string> {
    return this.invoke<string>(
      "get_solana_signer_address",
      compact({ accountId }),
    );
  }

  /**
   * Sign exact message bytes with the Majik Key Solana signer.
   * Only the 64-byte signature is returned; private key material remains in Rust.
   */
  async signSolanaMessage(
    message: Uint8Array,
    accountId?: string,
  ): Promise<Uint8Array> {
    const signature = await this.invoke<number[]>(
      "sign_solana_message",
      compact({ message: Array.from(message), accountId }),
    );
    if (
      !Array.isArray(signature) ||
      signature.length !== 64 ||
      !signature.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    ) {
      throw new Error("Rust returned an invalid Solana Ed25519 signature.");
    }
    return Uint8Array.from(signature);
  }

/** Invoke the native list_contacts operation. */
  listContacts(
    sortedByLabel?: boolean,
    majikahOnly?: boolean,
  ): Promise<SerializedMajikContact[]> {
    return this.invoke<SerializedMajikContact[]>(
      "list_contacts",
      compact({ sortedByLabel, majikahOnly }),
    );
  }

/** Invoke the native get_contact operation. */
  getContact(id: string): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact",
      compact({ id }),
    );
  }

/** Invoke the native get_contact_by_fingerprint operation. */
  getContactByFingerprint(
    fingerprint: string,
  ): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact_by_fingerprint",
      compact({ fingerprint }),
    );
  }

/** Invoke the native get_contact_by_address operation. */
  getContactByAddress(address: string): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact_by_address",
      compact({ address }),
    );
  }

/** Invoke the native add_contact operation. */
  addContact(contact: SerializedMajikContact): Promise<void> {
    return this.invoke<void>("add_contact", compact({ contact }));
  }

/** Invoke the native remove_contact operation. */
  removeContact(id: string): Promise<void> {
    return this.invoke<void>("remove_contact", compact({ id }));
  }

/** Invoke the native update_contact_meta operation. */
  updateContactMeta(id: string, meta: MajikContactMeta): Promise<void> {
    return this.invoke<void>("update_contact_meta", compact({ id, meta }));
  }

/** Invoke the native import_contact_from_json operation. */
  importContactFromJson(json: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>(
      "import_contact_from_json",
      compact({ json }),
    );
  }

/** Invoke the native import_contact_from_string operation. */
  importContactFromString(data: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>(
      "import_contact_from_string",
      compact({ data }),
    );
  }

/** Invoke the native export_contact_json operation. */
  exportContactJson(id: string): Promise<string | null> {
    return this.invoke<string | null>("export_contact_json", compact({ id }));
  }

/** Invoke the native export_contact_string operation. */
  exportContactString(id: string): Promise<string | null> {
    return this.invoke<string | null>("export_contact_string", compact({ id }));
  }

  /** Empty the directory; your own accounts' contacts are put back. */
/** Invoke the native clear_directory operation. */
  clearDirectory(): Promise<void> {
    return this.invoke<void>("clear_directory");
  }

/** Invoke the native set_majikah_status operation. */
  setMajikahStatus(
    id: string,
    status: boolean,
  ): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "set_majikah_status",
      compact({ id, status }),
    );
  }

/** Invoke the native block_contact operation. */
  blockContact(id: string): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "block_contact",
      compact({ id }),
    );
  }

/** Invoke the native unblock_contact operation. */
  unblockContact(id: string): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "unblock_contact",
      compact({ id }),
    );
  }

/** Invoke the native list_groups operation. */
  listGroups(
    includeSystem?: boolean,
    sortedByName?: boolean,
  ): Promise<SerializedMajikContactGroup[]> {
    return this.invoke<SerializedMajikContactGroup[]>(
      "list_groups",
      compact({ includeSystem, sortedByName }),
    );
  }

/** Invoke the native get_group operation. */
  getGroup(id: string): Promise<SerializedMajikContactGroup | null> {
    return this.invoke<SerializedMajikContactGroup | null>(
      "get_group",
      compact({ id }),
    );
  }

/** Invoke the native get_contacts_in_group operation. */
  getContactsInGroup(id: string): Promise<SerializedMajikContact[]> {
    return this.invoke<SerializedMajikContact[]>(
      "get_contacts_in_group",
      compact({ id }),
    );
  }

/** Invoke the native create_group operation. */
  createGroup(args: CreateGroupArgs): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "create_group",
      compact({ args }),
    );
  }

/** Invoke the native remove_group operation. */
  removeGroup(id: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>("remove_group", compact({ id }));
  }

/** Invoke the native update_group_meta operation. */
  updateGroupMeta(
    args: UpdateGroupMetaArgs,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "update_group_meta",
      compact({ args }),
    );
  }

/** Invoke the native add_contact_to_group operation. */
  addContactToGroup(
    groupId: string,
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contact_to_group",
      compact({ groupId, contactId }),
    );
  }

/** Invoke the native add_contacts_to_group operation. */
  addContactsToGroup(
    groupId: string,
    contactIds: string[],
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contacts_to_group",
      compact({ groupId, contactIds }),
    );
  }

/** Invoke the native remove_contact_from_group operation. */
  removeContactFromGroup(
    groupId: string,
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "remove_contact_from_group",
      compact({ groupId, contactId }),
    );
  }

/** Invoke the native move_contact_between_groups operation. */
  moveContactBetweenGroups(
    contactId: string,
    fromGroupId: string,
    toGroupId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "move_contact_between_groups",
      compact({ contactId, fromGroupId, toGroupId }),
    );
  }

/** Invoke the native add_contact_to_favorites operation. */
  addContactToFavorites(
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contact_to_favorites",
      compact({ contactId }),
    );
  }

/** Invoke the native remove_contact_from_favorites operation. */
  removeContactFromFavorites(
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "remove_contact_from_favorites",
      compact({ contactId }),
    );
  }

  /** The account must be unlocked (stamps are encrypted to its key). */
/** Invoke the native create_stamp operation. */
  createStamp(args: CreateStampArgs): Promise<StampMeta> {
    return this.invoke<StampMeta>("create_stamp", compact({ args }));
  }

/** Invoke the native list_stamps operation. */
  listStamps(kind?: StampAssetKind): Promise<StampMeta[]> {
    return this.invoke<StampMeta[]>("list_stamps", compact({ kind }));
  }

/** Invoke the native list_stamps_for_active_account operation. */
  listStampsForActiveAccount(): Promise<StampMeta[]> {
    return this.invoke<StampMeta[]>("list_stamps_for_active_account");
  }

  /** Load and decrypt the active account's stamps into memory. */
/** Invoke the native hydrate_stamps operation. */
  hydrateStamps(): Promise<SkippedItem[]> {
    return this.invoke<SkippedItem[]>("hydrate_stamps");
  }

  /** Wipe decrypted stamps from memory. */
/** Invoke the native lock_stamps operation. */
  lockStamps(): Promise<number> {
    return this.invoke<number>("lock_stamps");
  }

/** Invoke the native get_stamp operation. */
  getStamp(id: string): Promise<StampMeta | null> {
    return this.invoke<StampMeta | null>("get_stamp", compact({ id }));
  }

  /** Plaintext of a hydrated stamp; null if it is not hydrated. */
/** Invoke the native get_decrypted_stamp operation. */
  getDecryptedStamp(
    id: string,
    output?: OutputTarget,
  ): Promise<BytesOutput | null> {
    return this.invoke<BytesOutput | null>(
      "get_decrypted_stamp",
      compact({ id, output }),
    );
  }

/** Invoke the native decrypt_stamp_content operation. */
  decryptStampContent(
    id: string,
    accountId?: string,
    output?: OutputTarget,
  ): Promise<BytesOutput> {
    return this.invoke<BytesOutput>(
      "decrypt_stamp_content",
      compact({ id, accountId, output }),
    );
  }

/** Invoke the native rename_stamp operation. */
  renameStamp(id: string, name: string): Promise<StampMeta> {
    return this.invoke<StampMeta>("rename_stamp", compact({ id, name }));
  }

/** Invoke the native replace_stamp_content operation. */
  replaceStampContent(
    id: string,
    input: FileInput,
    mimeType?: string,
    accountId?: string,
  ): Promise<StampMeta> {
    return this.invoke<StampMeta>(
      "replace_stamp_content",
      compact({ id, input, mimeType, accountId }),
    );
  }

/** Invoke the native remove_stamp operation. */
  removeStamp(id: string): Promise<void> {
    return this.invoke<void>("remove_stamp", compact({ id }));
  }

/** Invoke the native inspect_stamp operation. */
  inspectStamp(
    input: FileInput,
  ): Promise<{ hasPixelRow: boolean; hasDct: boolean }> {
    return this.invoke<{ hasPixelRow: boolean; hasDct: boolean }>(
      "inspect_stamp",
      compact({ input }),
    );
  }

/** Invoke the native is_stamped operation. */
  isStamped(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_stamped", compact({ input }));
  }

/** Invoke the native sign_text operation. */
  signText(
    text: string,
    options?: SignTextOptions,
    ctx?: Ctx,
  ): Promise<SignTextResult> {
    return this.invoke<SignTextResult>(
      "sign_text",
      compact({ text, options, ctx }),
    );
  }

/** Invoke the native verify_text operation. */
  verifyText(args: VerifyTextArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_text", compact({ args }));
  }

/** Invoke the native get_signature_metadata operation. */
  getSignatureMetadata(serialized: string): Promise<SignatureMetadata> {
    return this.invoke<SignatureMetadata>(
      "get_signature_metadata",
      compact({ serialized }),
    );
  }

  /** Stream-sign a native file path and atomically publish the embedded output. */
/** Invoke the native sign_file_embedded_stream operation. */
  signFileEmbeddedStream(
    args: StreamingEmbeddedSignArgs,
  ): Promise<StreamingSignResult> {
    validateStreamingSignArgs(args);
    return this.invoke<StreamingSignResult>(
      "sign_file_embedded_stream",
      compact({ args }),
    );
  }

  /** Stream-sign a native file path and atomically publish a detached .mjksig envelope. */
/** Invoke the native sign_file_detached_stream operation. */
  signFileDetachedStream(
    args: StreamingDetachedSignArgs,
  ): Promise<StreamingSignResult> {
    validateStreamingSignArgs(args);
    return this.invoke<StreamingSignResult>(
      "sign_file_detached_stream",
      compact({ args }),
    );
  }

  /** Stream-sign an embedded revision using a native path to the prior signed file. */
/** Invoke the native sign_file_embedded_stream_with_prior operation. */
  signFileEmbeddedStreamWithPrior(
    args: StreamingEmbeddedRevisionArgs,
  ): Promise<StreamingSignResult> {
    validateStreamingSignArgs(args, args.priorFilePath);
    return this.invoke<StreamingSignResult>(
      "sign_file_embedded_stream_with_prior",
      compact({ args }),
    );
  }

  /** Stream-sign a detached revision using a native path to the prior signed file. */
/** Invoke the native sign_file_detached_stream_with_prior operation. */
  signFileDetachedStreamWithPrior(
    args: StreamingDetachedRevisionArgs,
  ): Promise<StreamingSignResult> {
    validateStreamingSignArgs(args, args.priorFilePath);
    return this.invoke<StreamingSignResult>(
      "sign_file_detached_stream_with_prior",
      compact({ args }),
    );
  }

  /** Verify an embedded signature directly from a native file path. */
/** Invoke the native verify_file_embedded_stream operation. */
  verifyFileEmbeddedStream(args: StreamingVerifyArgs): Promise<VerifyResult> {
    validateOperationId(args.operationId);
    validateNativePath(args.inputPath, "inputPath");
    validateStreamingOptions(args.streaming);
    validateVerificationTarget(args.target);
    return this.invoke<VerifyResult>(
      "verify_file_embedded_stream",
      compact({ args }),
    );
  }

  /** Verify a native file against a detached envelope path. */
/** Invoke the native verify_file_detached_stream operation. */
  verifyFileDetachedStream(
    args: StreamingDetachedVerifyArgs,
  ): Promise<VerifyResult> {
    validateOperationId(args.operationId);
    validateNativePath(args.inputPath, "inputPath");
    validateNativePath(args.envelopePath, "envelopePath");
    validateStreamingOptions(args.streaming);
    validateVerificationTarget(args.target);
    return this.invoke<VerifyResult>(
      "verify_file_detached_stream",
      compact({ args }),
    );
  }


  /**
   * Sign native paths as one MJKSMAP or a set of detached sidecars.
   *
   * Input metadata is validated before IPC; the Rust client opens and streams each source file.
   */
  signBatchDetachedPathsStream(
    args: StreamingBatchSignArgs,
  ): Promise<StreamingBatchSignResult> {
    validateOperationId(args.operationId);
    validateStreamingBatchInputs(args.inputs);
    validateBatchStreamingOptions(args.streaming);
    validateSigningMetadata(args.options);
    if (args.ctx?.accountId !== undefined) validateBoundedText(args.ctx.accountId, "accountId", 256);

    switch (args.options?.mode ?? "map") {
      case "map":
        validateNativePath(args.mapOutputPath ?? "", "mapOutputPath");
        break;
      case "separate":
        validateNativePath(args.outputDir ?? "", "outputDir");
        break;
      default:
        throw new TypeError("options.mode must be 'map' or 'separate'.");
    }

    return this.invoke<StreamingBatchSignResult>(
      "sign_batch_detached_paths_stream",
      compact({ args }),
    );
  }

  /**
   * Verify native file paths against an MJKSMAP using a trusted signer key.
   *
   * The Rust verifier requires an account, contact or address; it does not use self-reported keys.
   */
  verifyMjksMapPathsStream(
    args: StreamingBatchVerifyArgs,
  ): Promise<MapVerify> {
    validateOperationId(args.operationId);
    validateNativePath(args.mapPath, "mapPath");
    validateStreamingBatchInputs(args.inputs);
    validateBatchStreamingOptions(args.streaming);
    validateVerificationTarget(args.target, true);
    return this.invoke<MapVerify>(
      "verify_mjks_map_paths_stream",
      compact({ args }),
    );
  }

  /** Inspect current RAM availability, CPU concurrency and platform information. */
/** Invoke the native get_system_profile operation. */
  getSystemProfile(): Promise<SystemProfile> {
    return this.invoke<SystemProfile>("get_system_profile");
  }

  /** Retrieve the native plugin's current adaptive streaming recommendation. */
/** Invoke the native get_recommended_streaming_config operation. */
  getRecommendedStreamingConfig(): Promise<RecommendedStreamingConfig> {
    return this.invoke<RecommendedStreamingConfig>("get_recommended_streaming_config");
  }

  /** Request cancellation; resolves true only when the operation ID was active. */
/** Invoke the native cancel_stream operation. */
  cancelStream(operationId: string): Promise<boolean> {
    validateOperationId(operationId);
    return this.invoke<boolean>("cancel_stream", compact({ operationId }));
  }

  /** Sign `input` and embed the signature. Writes to `output.path`, or returns bytes inline. */
/** Invoke the native sign_file operation. */
  signFile(args: SignFileArgs): Promise<SignedFile> {
    return this.invoke<SignedFile>("sign_file", compact({ args }));
  }

  /** Sign `input` and produce a separate `.mjksig` envelope. */
/** Invoke the native sign_file_detached operation. */
  signFileDetached(args: SignDetachedArgs): Promise<DetachedSigned> {
    return this.invoke<DetachedSigned>("sign_file_detached", compact({ args }));
  }

  /** Sign a SignRoom document using the issued challenge and revision-chain commitment. */
/** Invoke the native sign_session_file operation. */
  signSessionFile(args: SignSessionFileArgs): Promise<SessionSigned> {
    return this.invoke<SessionSigned>("sign_session_file", compact({ args }));
  }

  /** Encrypt a SignRoom source with the owner's public key and pinned recipients. */
/** Invoke the native encrypt_sign_room_file operation. */
  encryptSignRoomFile(args: EncryptSignRoomFileArgs): Promise<EncryptSignRoomFileResult> {
    return this.invoke<EncryptSignRoomFileResult>(
      "encrypt_signroom_file",
      compact({ args }),
    );
  }

  /** Decrypt and verify a SignRoom MJKB with the selected local Majik Key. */
/** Invoke the native decrypt_sign_room_file operation. */
  decryptSignRoomFile(args: DecryptSignRoomFileArgs): Promise<DecryptSignRoomFileResult> {
    return this.invoke<DecryptSignRoomFileResult>(
      "decrypt_signroom_file",
      compact({ args }),
    );
  }

/** Invoke the native resign_file operation. */
  resignFile(args: ResignArgs): Promise<SignedFile> {
    return this.invoke<SignedFile>("resign_file", compact({ args }));
  }

/** Invoke the native batch_sign_files operation. */
  batchSignFiles(args: BatchSignFilesArgs): Promise<BatchSignOutcome[]> {
    return this.invoke<BatchSignOutcome[]>(
      "batch_sign_files",
      compact({ args }),
    );
  }

  /** Step 1 of a timestamped signature: sign, then POST `tsaRequest` to the TSA. */
/** Invoke the native begin_sign_file_with_tsa operation. */
  beginSignFileWithTsa(args: SignFileArgs): Promise<TsaBegin> {
    return this.invoke<TsaBegin>("begin_sign_file_with_tsa", compact({ args }));
  }

  /** Step 2: attach the TSA's timestamp and re-embed. */
/** Invoke the native complete_sign_file_with_tsa operation. */
  completeSignFileWithTsa(
    token: string,
    timestamp: MajikTimestamp,
    output?: OutputTarget,
  ): Promise<SignedFile> {
    return this.invoke<SignedFile>(
      "complete_sign_file_with_tsa",
      compact({ token, timestamp, output }),
    );
  }

/** Invoke the native begin_sign_file_detached_with_tsa operation. */
  beginSignFileDetachedWithTsa(args: SignDetachedArgs): Promise<TsaBegin> {
    return this.invoke<TsaBegin>(
      "begin_sign_file_detached_with_tsa",
      compact({ args }),
    );
  }

/** Invoke the native complete_sign_file_detached_with_tsa operation. */
  completeSignFileDetachedWithTsa(
    token: string,
    timestamp: MajikTimestamp,
    output?: OutputTarget,
  ): Promise<DetachedSigned> {
    return this.invoke<DetachedSigned>(
      "complete_sign_file_detached_with_tsa",
      compact({ token, timestamp, output }),
    );
  }

  /** Drop a pending signature (e.g. the TSA request failed). */
/** Invoke the native cancel_pending_tsa operation. */
  cancelPendingTsa(token: string): Promise<void> {
    return this.invoke<void>("cancel_pending_tsa", compact({ token }));
  }

/** Invoke the native verify_file operation. */
  verifyFile(args: VerifyFileArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_file", compact({ args }));
  }

/** Invoke the native verify_file_all_signatures operation. */
  verifyFileAllSignatures(args: VerifyFileArgs): Promise<VerifyResult[]> {
    return this.invoke<VerifyResult[]>(
      "verify_file_all_signatures",
      compact({ args }),
    );
  }

/** Invoke the native verify_file_detached operation. */
  verifyFileDetached(args: VerifyDetachedArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_file_detached", compact({ args }));
  }

/** Invoke the native verify_file_detached_all_signatures operation. */
  verifyFileDetachedAllSignatures(
    args: VerifyDetachedArgs,
  ): Promise<VerifyResult[]> {
    return this.invoke<VerifyResult[]>(
      "verify_file_detached_all_signatures",
      compact({ args }),
    );
  }

/** Invoke the native verify_file_chain operation. */
  verifyFileChain(input: FileInput, now?: string): Promise<FileChain> {
    return this.invoke<FileChain>("verify_file_chain", compact({ input, now }));
  }

/** Invoke the native verify_file_detached_chain operation. */
  verifyFileDetachedChain(
    input: FileInput,
    envelope: FileInput,
    now?: string,
  ): Promise<FileChain> {
    return this.invoke<FileChain>(
      "verify_file_detached_chain",
      compact({ input, envelope, now }),
    );
  }

/** Invoke the native verify_file_revisions operation. */
  verifyFileRevisions(
    finalFile: FileInput,
    revisions: FileInput[],
  ): Promise<RevisionSet> {
    return this.invoke<RevisionSet>(
      "verify_file_revisions",
      compact({ finalFile, revisions }),
    );
  }

/** Invoke the native verify_file_revisions_detached operation. */
  verifyFileRevisionsDetached(
    finalFile: FileInput,
    revisions: FileInput[],
    envelope: FileInput,
  ): Promise<RevisionSet> {
    return this.invoke<RevisionSet>(
      "verify_file_revisions_detached",
      compact({ finalFile, revisions, envelope }),
    );
  }

/** Invoke the native extract_signatures operation. */
  extractSignatures(input: FileInput): Promise<MajikSignatureJSON[]> {
    return this.invoke<MajikSignatureJSON[]>(
      "extract_signatures",
      compact({ input }),
    );
  }

/** Invoke the native strip_signature operation. */
  stripSignature(
    input: FileInput,
    output?: OutputTarget,
  ): Promise<BytesOutput> {
    return this.invoke<BytesOutput>(
      "strip_signature",
      compact({ input, output }),
    );
  }

/** Invoke the native is_file_signed operation. */
  isFileSigned(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_file_signed", compact({ input }));
  }

/** Invoke the native get_allowlist operation. */
  getAllowlist(input: FileInput): Promise<ExpectedSigner[] | null> {
    return this.invoke<ExpectedSigner[] | null>(
      "get_allowlist",
      compact({ input }),
    );
  }

/** Invoke the native can_sign operation. */
  canSign(input: FileInput, accountId?: string): Promise<Permit> {
    return this.invoke<Permit>("can_sign", compact({ input, accountId }));
  }

/** Invoke the native is_multi_sig operation. */
  isMultiSig(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_multi_sig", compact({ input }));
  }

/** Invoke the native get_signatories operation. */
  getSignatories(
    input: FileInput,
    filter?: SignatoriesFilter,
  ): Promise<Json | null> {
    return this.invoke<Json | null>(
      "get_signatories",
      compact({ input, filter }),
    );
  }

/** Invoke the native get_issuer operation. */
  getIssuer(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_issuer", compact({ input }));
  }

/** Invoke the native get_envelope_info operation. */
  getEnvelopeInfo(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_envelope_info", compact({ input }));
  }

/** Invoke the native get_file_signature_info operation. */
  getFileSignatureInfo(input: FileInput): Promise<FileSignatureInfo> {
    return this.invoke<FileSignatureInfo>(
      "get_file_signature_info",
      compact({ input }),
    );
  }

  /** Seal a file: no further signatures can be added. */
/** Invoke the native seal operation. */
  seal(
    input: FileInput,
    output?: OutputTarget,
    ctx?: Ctx,
  ): Promise<SealedFile> {
    return this.invoke<SealedFile>("seal", compact({ input, output, ctx }));
  }

/** Invoke the native verify_seal operation. */
  verifySeal(input: FileInput): Promise<Json> {
    return this.invoke<Json>("verify_seal", compact({ input }));
  }

/** Invoke the native get_seal_info operation. */
  getSealInfo(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_seal_info", compact({ input }));
  }

/** Invoke the native is_sealed operation. */
  isSealed(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_sealed", compact({ input }));
  }

  /** Whether the file may be anchored on-chain (it must be sealed). Local check. */
/** Invoke the native can_anchor operation. */
  canAnchor(input: FileInput): Promise<Permit> {
    return this.invoke<Permit>("can_anchor", compact({ input }));
  }

  /** Embed a confirmed anchor into the file. Local, no network. */
/** Invoke the native register_chain_anchor operation. */
  registerChainAnchor(
    input: FileInput,
    anchor: MajikChainAnchor,
    output?: OutputTarget,
  ): Promise<BytesOutput> {
    return this.invoke<BytesOutput>(
      "register_chain_anchor",
      compact({ input, anchor, output }),
    );
  }

/** Invoke the native describe_mjks_map operation. */
  describeMjksMap(input: FileInput): Promise<MapFileInfo[]> {
    return this.invoke<MapFileInfo[]>("describe_mjks_map", compact({ input }));
  }

/** Invoke the native is_mjks_map operation. */
  isMjksMap(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_mjks_map", compact({ input }));
  }

/** Invoke the native sign_batch_detached operation. */
  signBatchDetached(args: BatchDetachedArgs): Promise<BatchDetached> {
    return this.invoke<BatchDetached>("sign_batch_detached", compact({ args }));
  }

/** Invoke the native cosign_mjks_map operation. */
  cosignMjksMap(args: CosignArgs): Promise<Cosign> {
    return this.invoke<Cosign>("cosign_mjks_map", compact({ args }));
  }

/** Invoke the native verify_mjks_map operation. */
  verifyMjksMap(args: VerifyMapArgs): Promise<MapVerify> {
    return this.invoke<MapVerify>("verify_mjks_map", compact({ args }));
  }

  /** Check signing order (pass `envelope` for a detached signature). */
/** Invoke the native verify_file_order operation. */
  verifyFileOrder(args: OrderArgs): Promise<Json> {
    return this.invoke<Json>("verify_file_order", compact({ args }));
  }

/** Invoke the native verify_mjks_map_order operation. */
  verifyMjksMapOrder(
    map: FileInput,
    files: FileInput[],
    expected: SignerRef[],
    strict?: boolean,
    source?: HistorySource,
  ): Promise<MapOrder[]> {
    return this.invoke<MapOrder[]>(
      "verify_mjks_map_order",
      compact({ map, files, expected, strict, source }),
    );
  }

/** Invoke the native backup_contacts operation. */
  backupContacts(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_contacts", compact({ output }));
  }

/** Invoke the native backup_stamps operation. */
  backupStamps(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_stamps", compact({ output }));
  }

/** Invoke the native backup_app_data operation. */
  backupAppData(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_app_data", compact({ output }));
  }

/** Invoke the native probe_backup_type operation. */
  probeBackupType(input: FileInput): Promise<BackupType> {
    return this.invoke<BackupType>("probe_backup_type", compact({ input }));
  }

/** Invoke the native read_app_data_backup operation. */
  readAppDataBackup(input: FileInput): Promise<AppDataSummary> {
    return this.invoke<AppDataSummary>(
      "read_app_data_backup",
      compact({ input }),
    );
  }

/** Invoke the native restore_contacts operation. */
  restoreContacts(
    input: FileInput,
    overwriteContacts?: boolean,
    includeGroups?: boolean,
  ): Promise<{ contacts: number; groups: number }> {
    return this.invoke<{ contacts: number; groups: number }>(
      "restore_contacts",
      compact({ input, overwriteContacts, includeGroups }),
    );
  }

/** Invoke the native restore_stamps operation. */
  restoreStamps(input: FileInput): Promise<number> {
    return this.invoke<number>("restore_stamps", compact({ input }));
  }

/** Invoke the native restore_app_data operation. */
  restoreAppData(
    input: FileInput,
  ): Promise<{ contacts: number; groups: number; stamps: number }> {
    return this.invoke<{ contacts: number; groups: number; stamps: number }>(
      "restore_app_data",
      compact({ input }),
    );
  }

/** Invoke the native restore_app_data_selective operation. */
  restoreAppDataSelective(
    input: FileInput,
    options?: SelectiveRestoreOptions,
  ): Promise<{
    contacts: number;
    groups: number;
    stamps: number;
    preferences: boolean;
  }> {
    return this.invoke<{
      contacts: number;
      groups: number;
      stamps: number;
      preferences: boolean;
    }>("restore_app_data_selective", compact({ input, options }));
  }
}
