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
  validateOperationId(args.operationId);
  validateNativePath(args.inputPath, "inputPath");
  validateNativePath(args.outputPath, "outputPath");
  validateStreamingOptions(args.streaming);
  if (priorFilePath !== undefined) validateNativePath(priorFilePath, "priorFilePath");
  if (args.ctx?.accountId !== undefined) validateBoundedText(args.ctx.accountId, "accountId", 256);
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

  constructor(options: MajikSignatureClientTauriOptions = {}) {
    super({
      plugin: SIGNATURE_PLUGIN,
      eventChannel: SIGNATURE_EVENT_CHANNEL,
      ...options,
    });
  }

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
  onStreamProgress(
    listener: (payload: StreamingProgressPayload) => void,
  ): () => void {
    this.streamProgressListeners.add(listener);
    return () => this.streamProgressListeners.delete(listener);
  }

  /** Stop progress notifications before disposing the inherited key/signature session. */
  override async dispose(): Promise<void> {
    this.unlistenStreamProgress?.();
    this.unlistenStreamProgress = null;
    this.streamProgressListeners.clear();
    await super.dispose();
  }

  /** Build the current Rust snapshot without rehydrating storage. */
  snapshotSignatureClient(): Promise<unknown> {
    return this.invoke<unknown>("snapshot");
  }

  /** Open the signature session and hydrate the Rust client if needed. */
  openSignatureSession(): Promise<OpenedSession> {
    return this.invoke<OpenedSession>("open_session");
  }

  /** Reload contacts, logs, stamps and keys from storage without clobbering the key client setup. */
  hydrateSignatureClient(): Promise<SigHydrateReport> {
    return this.invoke<SigHydrateReport>("hydrate");
  }

  /** Reset managed signature data while preserving audit history. */
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
  override updateAccountLabel(id: string, label: string): Promise<void> {
    return super.updateAccountLabel(id, label);
  }

  /** Update an own account's contact meta (a non-empty label also renames the key). */
  updateOwnAccountMeta(id: string, meta: MajikContactMeta): Promise<void> {
    return this.invoke<void>("update_own_account_meta", compact({ id, meta }));
  }

  getUserAppPreferences(): Promise<UserAppPreferences> {
    return this.invoke<UserAppPreferences>("get_user_app_preferences");
  }

  setUserAppPreferences(preferences: UserAppPreferences): Promise<void> {
    return this.invoke<void>(
      "set_user_app_preferences",
      compact({ preferences }),
    );
  }

  resetUserAppPreferences(): Promise<void> {
    return this.invoke<void>("reset_user_app_preferences");
  }

  /** History entries of the active account. */
  listHistoryLogs(): Promise<HistoryLog[]> {
    return this.invoke<HistoryLog[]>("list_history_logs");
  }

  /** Audit entries of the active account. */
  listActivityLogs(): Promise<UserActivityLog[]> {
    return this.invoke<UserActivityLog[]>("list_activity_logs");
  }

  clearHistoryLogs(): Promise<void> {
    return this.invoke<void>("clear_history_logs");
  }

  clearActivityLogs(): Promise<void> {
    return this.invoke<void>("clear_activity_logs");
  }

  /** Clear both logs for the active account and leave a restart audit entry. */
  restartLogs(): Promise<void> {
    return this.invoke<void>("restart_logs");
  }

  hydrateLogs(): Promise<void> {
    return this.invoke<void>("hydrate_logs");
  }

  /** Own-account label, else contact label, else a shortened id. */
  resolveSignerLabel(signerId: string): Promise<string> {
    return this.invoke<string>("resolve_signer_label", compact({ signerId }));
  }

  /** Unlock once for several signing operations; pair with `endSigningSession()`. */
  beginSigningSession(accountId?: string): Promise<void> {
    return this.invoke<void>("begin_signing_session", compact({ accountId }));
  }

  endSigningSession(): Promise<void> {
    return this.invoke<void>("end_signing_session");
  }

  forceEndSigningSession(): Promise<void> {
    return this.invoke<void>("force_end_signing_session");
  }

  isSigningSessionActive(): Promise<boolean> {
    return this.invoke<boolean>("is_signing_session_active");
  }

  /** Resolve the account's domain-separated Majik Key Solana signer address. */
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

  listContacts(
    sortedByLabel?: boolean,
    majikahOnly?: boolean,
  ): Promise<SerializedMajikContact[]> {
    return this.invoke<SerializedMajikContact[]>(
      "list_contacts",
      compact({ sortedByLabel, majikahOnly }),
    );
  }

  getContact(id: string): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact",
      compact({ id }),
    );
  }

  getContactByFingerprint(
    fingerprint: string,
  ): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact_by_fingerprint",
      compact({ fingerprint }),
    );
  }

  getContactByAddress(address: string): Promise<SerializedMajikContact | null> {
    return this.invoke<SerializedMajikContact | null>(
      "get_contact_by_address",
      compact({ address }),
    );
  }

  addContact(contact: SerializedMajikContact): Promise<void> {
    return this.invoke<void>("add_contact", compact({ contact }));
  }

  removeContact(id: string): Promise<void> {
    return this.invoke<void>("remove_contact", compact({ id }));
  }

  updateContactMeta(id: string, meta: MajikContactMeta): Promise<void> {
    return this.invoke<void>("update_contact_meta", compact({ id, meta }));
  }

  importContactFromJson(json: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>(
      "import_contact_from_json",
      compact({ json }),
    );
  }

  importContactFromString(data: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>(
      "import_contact_from_string",
      compact({ data }),
    );
  }

  exportContactJson(id: string): Promise<string | null> {
    return this.invoke<string | null>("export_contact_json", compact({ id }));
  }

  exportContactString(id: string): Promise<string | null> {
    return this.invoke<string | null>("export_contact_string", compact({ id }));
  }

  /** Empty the directory; your own accounts' contacts are put back. */
  clearDirectory(): Promise<void> {
    return this.invoke<void>("clear_directory");
  }

  setMajikahStatus(
    id: string,
    status: boolean,
  ): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "set_majikah_status",
      compact({ id, status }),
    );
  }

  blockContact(id: string): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "block_contact",
      compact({ id }),
    );
  }

  unblockContact(id: string): Promise<SerializedMajikContact> {
    return this.invoke<SerializedMajikContact>(
      "unblock_contact",
      compact({ id }),
    );
  }

  listGroups(
    includeSystem?: boolean,
    sortedByName?: boolean,
  ): Promise<SerializedMajikContactGroup[]> {
    return this.invoke<SerializedMajikContactGroup[]>(
      "list_groups",
      compact({ includeSystem, sortedByName }),
    );
  }

  getGroup(id: string): Promise<SerializedMajikContactGroup | null> {
    return this.invoke<SerializedMajikContactGroup | null>(
      "get_group",
      compact({ id }),
    );
  }

  getContactsInGroup(id: string): Promise<SerializedMajikContact[]> {
    return this.invoke<SerializedMajikContact[]>(
      "get_contacts_in_group",
      compact({ id }),
    );
  }

  createGroup(args: CreateGroupArgs): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "create_group",
      compact({ args }),
    );
  }

  removeGroup(id: string): Promise<ApiResponse> {
    return this.invoke<ApiResponse>("remove_group", compact({ id }));
  }

  updateGroupMeta(
    args: UpdateGroupMetaArgs,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "update_group_meta",
      compact({ args }),
    );
  }

  addContactToGroup(
    groupId: string,
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contact_to_group",
      compact({ groupId, contactId }),
    );
  }

  addContactsToGroup(
    groupId: string,
    contactIds: string[],
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contacts_to_group",
      compact({ groupId, contactIds }),
    );
  }

  removeContactFromGroup(
    groupId: string,
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "remove_contact_from_group",
      compact({ groupId, contactId }),
    );
  }

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

  addContactToFavorites(
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "add_contact_to_favorites",
      compact({ contactId }),
    );
  }

  removeContactFromFavorites(
    contactId: string,
  ): Promise<SerializedMajikContactGroup> {
    return this.invoke<SerializedMajikContactGroup>(
      "remove_contact_from_favorites",
      compact({ contactId }),
    );
  }

  /** The account must be unlocked (stamps are encrypted to its key). */
  createStamp(args: CreateStampArgs): Promise<StampMeta> {
    return this.invoke<StampMeta>("create_stamp", compact({ args }));
  }

  listStamps(kind?: StampAssetKind): Promise<StampMeta[]> {
    return this.invoke<StampMeta[]>("list_stamps", compact({ kind }));
  }

  listStampsForActiveAccount(): Promise<StampMeta[]> {
    return this.invoke<StampMeta[]>("list_stamps_for_active_account");
  }

  /** Load and decrypt the active account's stamps into memory. */
  hydrateStamps(): Promise<SkippedItem[]> {
    return this.invoke<SkippedItem[]>("hydrate_stamps");
  }

  /** Wipe decrypted stamps from memory. */
  lockStamps(): Promise<number> {
    return this.invoke<number>("lock_stamps");
  }

  getStamp(id: string): Promise<StampMeta | null> {
    return this.invoke<StampMeta | null>("get_stamp", compact({ id }));
  }

  /** Plaintext of a hydrated stamp; null if it is not hydrated. */
  getDecryptedStamp(
    id: string,
    output?: OutputTarget,
  ): Promise<BytesOutput | null> {
    return this.invoke<BytesOutput | null>(
      "get_decrypted_stamp",
      compact({ id, output }),
    );
  }

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

  renameStamp(id: string, name: string): Promise<StampMeta> {
    return this.invoke<StampMeta>("rename_stamp", compact({ id, name }));
  }

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

  removeStamp(id: string): Promise<void> {
    return this.invoke<void>("remove_stamp", compact({ id }));
  }

  inspectStamp(
    input: FileInput,
  ): Promise<{ hasPixelRow: boolean; hasDct: boolean }> {
    return this.invoke<{ hasPixelRow: boolean; hasDct: boolean }>(
      "inspect_stamp",
      compact({ input }),
    );
  }

  isStamped(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_stamped", compact({ input }));
  }

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

  verifyText(args: VerifyTextArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_text", compact({ args }));
  }

  getSignatureMetadata(serialized: string): Promise<SignatureMetadata> {
    return this.invoke<SignatureMetadata>(
      "get_signature_metadata",
      compact({ serialized }),
    );
  }

  /** Stream-sign a native file path and atomically publish the embedded output. */
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
  getSystemProfile(): Promise<SystemProfile> {
    return this.invoke<SystemProfile>("get_system_profile");
  }

  /** Retrieve the native plugin's current adaptive streaming recommendation. */
  getRecommendedStreamingConfig(): Promise<RecommendedStreamingConfig> {
    return this.invoke<RecommendedStreamingConfig>("get_recommended_streaming_config");
  }

  /** Request cancellation; resolves true only when the operation ID was active. */
  cancelStream(operationId: string): Promise<boolean> {
    validateOperationId(operationId);
    return this.invoke<boolean>("cancel_stream", compact({ operationId }));
  }

  /** Sign `input` and embed the signature. Writes to `output.path`, or returns bytes inline. */
  signFile(args: SignFileArgs): Promise<SignedFile> {
    return this.invoke<SignedFile>("sign_file", compact({ args }));
  }

  /** Sign `input` and produce a separate `.mjksig` envelope. */
  signFileDetached(args: SignDetachedArgs): Promise<DetachedSigned> {
    return this.invoke<DetachedSigned>("sign_file_detached", compact({ args }));
  }

  /** Sign a SignRoom document using the issued challenge and revision-chain commitment. */
  signSessionFile(args: SignSessionFileArgs): Promise<SessionSigned> {
    return this.invoke<SessionSigned>("sign_session_file", compact({ args }));
  }

  /** Encrypt a SignRoom source with the owner's public key and pinned recipients. */
  encryptSignRoomFile(args: EncryptSignRoomFileArgs): Promise<EncryptSignRoomFileResult> {
    return this.invoke<EncryptSignRoomFileResult>(
      "encrypt_signroom_file",
      compact({ args }),
    );
  }

  /** Decrypt and verify a SignRoom MJKB with the selected local Majik Key. */
  decryptSignRoomFile(args: DecryptSignRoomFileArgs): Promise<DecryptSignRoomFileResult> {
    return this.invoke<DecryptSignRoomFileResult>(
      "decrypt_signroom_file",
      compact({ args }),
    );
  }

  resignFile(args: ResignArgs): Promise<SignedFile> {
    return this.invoke<SignedFile>("resign_file", compact({ args }));
  }

  batchSignFiles(args: BatchSignFilesArgs): Promise<BatchSignOutcome[]> {
    return this.invoke<BatchSignOutcome[]>(
      "batch_sign_files",
      compact({ args }),
    );
  }

  /** Step 1 of a timestamped signature: sign, then POST `tsaRequest` to the TSA. */
  beginSignFileWithTsa(args: SignFileArgs): Promise<TsaBegin> {
    return this.invoke<TsaBegin>("begin_sign_file_with_tsa", compact({ args }));
  }

  /** Step 2: attach the TSA's timestamp and re-embed. */
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

  beginSignFileDetachedWithTsa(args: SignDetachedArgs): Promise<TsaBegin> {
    return this.invoke<TsaBegin>(
      "begin_sign_file_detached_with_tsa",
      compact({ args }),
    );
  }

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
  cancelPendingTsa(token: string): Promise<void> {
    return this.invoke<void>("cancel_pending_tsa", compact({ token }));
  }

  verifyFile(args: VerifyFileArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_file", compact({ args }));
  }

  verifyFileAllSignatures(args: VerifyFileArgs): Promise<VerifyResult[]> {
    return this.invoke<VerifyResult[]>(
      "verify_file_all_signatures",
      compact({ args }),
    );
  }

  verifyFileDetached(args: VerifyDetachedArgs): Promise<VerifyResult> {
    return this.invoke<VerifyResult>("verify_file_detached", compact({ args }));
  }

  verifyFileDetachedAllSignatures(
    args: VerifyDetachedArgs,
  ): Promise<VerifyResult[]> {
    return this.invoke<VerifyResult[]>(
      "verify_file_detached_all_signatures",
      compact({ args }),
    );
  }

  verifyFileChain(input: FileInput, now?: string): Promise<FileChain> {
    return this.invoke<FileChain>("verify_file_chain", compact({ input, now }));
  }

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

  verifyFileRevisions(
    finalFile: FileInput,
    revisions: FileInput[],
  ): Promise<RevisionSet> {
    return this.invoke<RevisionSet>(
      "verify_file_revisions",
      compact({ finalFile, revisions }),
    );
  }

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

  extractSignatures(input: FileInput): Promise<MajikSignatureJSON[]> {
    return this.invoke<MajikSignatureJSON[]>(
      "extract_signatures",
      compact({ input }),
    );
  }

  stripSignature(
    input: FileInput,
    output?: OutputTarget,
  ): Promise<BytesOutput> {
    return this.invoke<BytesOutput>(
      "strip_signature",
      compact({ input, output }),
    );
  }

  isFileSigned(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_file_signed", compact({ input }));
  }

  getAllowlist(input: FileInput): Promise<ExpectedSigner[] | null> {
    return this.invoke<ExpectedSigner[] | null>(
      "get_allowlist",
      compact({ input }),
    );
  }

  canSign(input: FileInput, accountId?: string): Promise<Permit> {
    return this.invoke<Permit>("can_sign", compact({ input, accountId }));
  }

  isMultiSig(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_multi_sig", compact({ input }));
  }

  getSignatories(
    input: FileInput,
    filter?: SignatoriesFilter,
  ): Promise<Json | null> {
    return this.invoke<Json | null>(
      "get_signatories",
      compact({ input, filter }),
    );
  }

  getIssuer(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_issuer", compact({ input }));
  }

  getEnvelopeInfo(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_envelope_info", compact({ input }));
  }

  getFileSignatureInfo(input: FileInput): Promise<FileSignatureInfo> {
    return this.invoke<FileSignatureInfo>(
      "get_file_signature_info",
      compact({ input }),
    );
  }

  /** Seal a file: no further signatures can be added. */
  seal(
    input: FileInput,
    output?: OutputTarget,
    ctx?: Ctx,
  ): Promise<SealedFile> {
    return this.invoke<SealedFile>("seal", compact({ input, output, ctx }));
  }

  verifySeal(input: FileInput): Promise<Json> {
    return this.invoke<Json>("verify_seal", compact({ input }));
  }

  getSealInfo(input: FileInput): Promise<Json | null> {
    return this.invoke<Json | null>("get_seal_info", compact({ input }));
  }

  isSealed(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_sealed", compact({ input }));
  }

  /** Whether the file may be anchored on-chain (it must be sealed). Local check. */
  canAnchor(input: FileInput): Promise<Permit> {
    return this.invoke<Permit>("can_anchor", compact({ input }));
  }

  /** Embed a confirmed anchor into the file. Local, no network. */
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

  describeMjksMap(input: FileInput): Promise<MapFileInfo[]> {
    return this.invoke<MapFileInfo[]>("describe_mjks_map", compact({ input }));
  }

  isMjksMap(input: FileInput): Promise<boolean> {
    return this.invoke<boolean>("is_mjks_map", compact({ input }));
  }

  signBatchDetached(args: BatchDetachedArgs): Promise<BatchDetached> {
    return this.invoke<BatchDetached>("sign_batch_detached", compact({ args }));
  }

  cosignMjksMap(args: CosignArgs): Promise<Cosign> {
    return this.invoke<Cosign>("cosign_mjks_map", compact({ args }));
  }

  verifyMjksMap(args: VerifyMapArgs): Promise<MapVerify> {
    return this.invoke<MapVerify>("verify_mjks_map", compact({ args }));
  }

  /** Check signing order (pass `envelope` for a detached signature). */
  verifyFileOrder(args: OrderArgs): Promise<Json> {
    return this.invoke<Json>("verify_file_order", compact({ args }));
  }

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

  backupContacts(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_contacts", compact({ output }));
  }

  backupStamps(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_stamps", compact({ output }));
  }

  backupAppData(output?: OutputTarget): Promise<BytesOutput> {
    return this.invoke<BytesOutput>("backup_app_data", compact({ output }));
  }

  probeBackupType(input: FileInput): Promise<BackupType> {
    return this.invoke<BackupType>("probe_backup_type", compact({ input }));
  }

  readAppDataBackup(input: FileInput): Promise<AppDataSummary> {
    return this.invoke<AppDataSummary>(
      "read_app_data_backup",
      compact({ input }),
    );
  }

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

  restoreStamps(input: FileInput): Promise<number> {
    return this.invoke<number>("restore_stamps", compact({ input }));
  }

  restoreAppData(
    input: FileInput,
  ): Promise<{ contacts: number; groups: number; stamps: number }> {
    return this.invoke<{ contacts: number; groups: number; stamps: number }>(
      "restore_app_data",
      compact({ input }),
    );
  }

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
