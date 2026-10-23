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
  SignedFile,
  SignerRef,
  SignFileArgs,
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

export const SIGNATURE_PLUGIN = "majik-signature-client";
export const SIGNATURE_EVENT_CHANNEL = "majik-signature-client:event";

export type MajikSignatureClientTauriOptions = MajikKeyClientTauriOptions;

/** Drop `undefined` values: serde treats a missing key differently from an explicit `null`. */
function compact(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  );
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

  constructor(options: MajikSignatureClientTauriOptions = {}) {
    super({
      plugin: SIGNATURE_PLUGIN,
      eventChannel: SIGNATURE_EVENT_CHANNEL,
      ...options,
    });
  }

  protected override async initialize(): Promise<OpenedSession> {
    const opened = await super.initialize();
    this.lastSigHydrateReport =
      opened.report as unknown as SigHydrateReport | null;
    return opened;
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
    return this.mutate<void>("update_own_account_meta", compact({ id, meta }));
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

  /** Sign `input` and embed the signature. Writes to `output.path`, or returns bytes inline. */
  signFile(args: SignFileArgs): Promise<SignedFile> {
    return this.invoke<SignedFile>("sign_file", compact({ args }));
  }

  /** Sign `input` and produce a separate `.mjksig` envelope. */
  signFileDetached(args: SignDetachedArgs): Promise<DetachedSigned> {
    return this.invoke<DetachedSigned>("sign_file_detached", compact({ args }));
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

  verifyFileRevisions(
    finalFile: FileInput,
    revisions: FileInput[],
  ): Promise<RevisionSet> {
    return this.invoke<RevisionSet>(
      "verify_file_revisions",
      compact({ finalFile, revisions }),
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
