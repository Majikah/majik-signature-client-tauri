# @majikah/majik-signature-client-tauri

TypeScript facade over `tauri-plugin-majik-signature-client`. Extends `MajikKeyClientTauri` (accounts, lock/unlock,
passphrases, synchronous read-model and its events) and adds contacts, groups, stamps, logs, preferences, signing and
verification, seals, signature maps and backups. 104 typed methods, generated from `gen.py`.

```ts
const majik = await MajikSignatureClientTauri.open({ onUnlockRequested: askForPassphrase });

const signed = await majik.signFile({
  input: { path: "C:\\docs\\contract.pdf" },
  output: { path: "C:\\docs\\contract.signed.pdf" },
});
const result = await majik.verifyFile({ input: { path: signed.file.path! }, target: { accountId: majik.getActiveAccountId()! } });

await majik.withSigningSession(undefined, async () => { /* several signs, one unlock */ });
majik.onSig("new-stamp", (stamp) => {});
```
Files: pass `{ path }` (Rust reads/validates; nothing large crosses IPC) or, for small blobs, `await toFileInput(blob)`.
Results: `output.path` writes to disk; otherwise read `outputBytes(result.file)` / `outputBlob(...)`.
Errors are `MajikKeyClientError` with `.kind` (`unlockRequired`, `fileNotFound`, `fileNotAFile`, `fileUnreadable`, `fileEmpty`,
`fileTooLarge`, `fileInvalid`, `fileExists`, `fileWriteFailed`, ...).

Subclass it for online features (`MajikSignatureClientDatabase`): `this.invoke()` for any command, your own axios layer on top.
`npm run build` first builds `../majik-key-client-tauri-ts` (a `file:` dependency).
