# @majikah/majik-signature-client-tauri

TypeScript facade over `tauri-plugin-majik-signature-client`. Extends `MajikKeyClientTauri` (accounts, lock/unlock,
passphrases, synchronous read-model and its events) and adds contacts, groups, stamps, logs, preferences, signing and
verification, seals, signature maps, backups, and bounded-memory native-path streaming. 113 typed methods.

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

## Native-path streaming

For multi-gigabyte files, use the streaming methods instead of the legacy `FileInput` methods.
They pass native paths directly to Rust and return metadata rather than materializing file bytes
in the webview.

```ts
const operationId = crypto.randomUUID();
const unsubscribe = majik.onStreamProgress((progress) => {
  if (progress.operationId === operationId) {
    console.info(progress.bytesProcessed, progress.totalBytes);
  }
});

const signed = await majik.signFileEmbeddedStream({
  operationId,
  inputPath: "C:\\docs\\large-video.mov",
  outputPath: "C:\\docs\\large-video.signed.mov",
  streaming: { chunkSize: 4 * 1024 * 1024 },
});

unsubscribe();
console.info(signed.output.path, signed.output.sizeBytes);
```

The facade also exposes `signFileDetachedStream`,
`signFileEmbeddedStreamWithPrior`, `signFileDetachedStreamWithPrior`,
`verifyFileEmbeddedStream`, and `verifyFileDetachedStream`. Revision methods take
`priorFilePath`; they do not accept an in-memory prior file. Use `cancelStream(operationId)`
to request cancellation, and `onStreamProgress()` to observe progress. A progress event contains
`operationId`, `bytesProcessed`, and nullable `totalBytes`; it is delivered on the dedicated
`majik-signature-client:stream-progress` channel to avoid unnecessary read-model refreshes.

Streaming options accept a preferred `chunkSize` between 64 KiB and 64 MiB. Omit it or set it to `null` to use the native system recommendation. Allocation failures automatically retry with the system recommendation and progressively smaller sizes; set `strictChunkSize: true` to disable fallback. The automatic recommendation is capped at 64 MiB, while 64 MiB is the maximum explicit override. Signing writes atomically to `outputPath`; `overwrite` defaults to `false`. The detached envelope input remains separately bounded by Rust.

Use `getSystemProfile()` and `getRecommendedStreamingConfig()` to inspect the native resource profile and current recommendation. Streaming commands resolve their own recommendation at operation start, so callers do not need to query it before every operation. Progress updates include the effective chunk size, attempt number and whether adaptive fallback is active.


Subclass it for online features (`MajikSignatureClientDatabase`): `this.invoke()` for any command, your own axios layer on top.
`npm run build` first builds `../majik-key-client-tauri-ts` (a `file:` dependency).


## Native-path streaming batches (1.6.0)

Version 1.6.0 exposes the Rust client's detached batch signing and MJKSMAP streaming verification. Source file bytes stay on disk and do not cross webview IPC.

```ts
const unsubscribe = majik.onStreamProgress((progress) => {
  // Batch progress also includes fileIndex, totalFiles and the manifest path.
  console.info(progress.path, progress.bytesProcessed, progress.totalBytes);
});

const signed = await majik.signBatchDetachedPathsStream({
  operationId: crypto.randomUUID(),
  inputs: [
    { manifestPath: "contracts/nda.pdf", sourcePath: "C:/docs/nda.pdf" },
    { manifestPath: "media/demo.mov", sourcePath: "C:/media/demo.mov" },
  ],
  mapOutputPath: "C:/output/contracts.mjksmap",
  options: { mode: "map", continueOnError: true },
  streaming: { chunkSize: 4 * 1024 * 1024, maxBytesPerFile: 10 * 1024 * 1024 * 1024 },
});

const verification = await majik.verifyMjksMapPathsStream({
  operationId: crypto.randomUUID(),
  mapPath: "C:/output/contracts.mjksmap",
  inputs: [
    { manifestPath: "contracts/nda.pdf", sourcePath: "C:/docs/nda.pdf" },
    { manifestPath: "media/demo.mov", sourcePath: "C:/media/demo.mov" },
  ],
  target: { accountId: majik.getActiveAccountId()! }, // trusted key required
  streaming: { chunkSize: 4 * 1024 * 1024 },
});

unsubscribe();
```

Separate output mode requires `outputDir` instead of `mapOutputPath` and writes unique numbered sidecars. Streaming MJKSMAP verification requires a trusted account, contact or address key; it does not use self-reported keys. Batch input is limited to 10,000 files, 4,096 UTF-16 code units per native or manifest path, 1,024 code units per MIME value, and 8 MiB of aggregate path/MIME metadata. The map file is limited to 64 MiB. Chunk sizes are 64 KiB–64 MiB. `maxBytesPerFile` is optional; omitting it does not impose an arbitrary total source-size cap.

The TypeScript facade performs early checks for paths, operation IDs, metadata, chunk sizes, duplicate manifest aliases, batch counts and trusted verification targets. The Rust plugin repeats validation because IPC arguments are untrusted. Native paths are not sandboxed by this package; the host app must configure Tauri capabilities and OS permissions.
## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-signature-client-tauri](https://github.com/Majikah/majik-signature-client-tauri)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)