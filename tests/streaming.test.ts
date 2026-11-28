import { describe, expect, it, vi } from "vitest";

import {
  MajikSignatureClientTauri,
  SIGNATURE_EVENT_CHANNEL,
  SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL,
} from "../src/index.js";
import type { Transport } from "../src/index.js";

type Listener = (payload: unknown) => void;

class FakeTransport implements Transport {
  calls: Array<{ command: string; args: Record<string, unknown> | undefined }> = [];
  private readonly listeners = new Map<string, Set<Listener>>();

  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push({ command, args });
    if (command === "open_session") {
      return {
        report: null,
        snapshot: { accounts: [], activeAccountId: null, status: [] },
      } as T;
    }
    return undefined as T;
  }

  async listen<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
    const listeners = this.listeners.get(event) ?? new Set<Listener>();
    const wrapped = handler as unknown as Listener;
    listeners.add(wrapped);
    this.listeners.set(event, listeners);

    return () => {
      listeners.delete(wrapped);
      if (listeners.size === 0) this.listeners.delete(event);
    };
  }

  emit<T>(event: string, payload: T): void {
    for (const listener of this.listeners.get(event) ?? []) listener(payload);
  }

  activeListeners(event: string): number {
    return this.listeners.get(event)?.size ?? 0;
  }

  count(command: string): number {
    return this.calls.filter((call) => call.command === command).length;
  }
}

describe("native-path streaming facade", () => {
  it("maps every streaming facade method to its Rust command", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });

    const signArgs = {
      operationId: "op-embedded",
      inputPath: "/tmp/source.mov",
      outputPath: "/tmp/signed.mov",
    };
    const detachedArgs = {
      operationId: "op-detached",
      inputPath: "/tmp/source.mov",
      outputPath: "/tmp/source.mjksig",
    };
    const verifyArgs = {
      operationId: "op-verify",
      inputPath: "/tmp/signed.mov",
    };
    const detachedVerifyArgs = {
      operationId: "op-verify-detached",
      inputPath: "/tmp/source.mov",
      envelopePath: "/tmp/source.mjksig",
    };

    await client.signFileEmbeddedStream(signArgs);
    await client.signFileDetachedStream(detachedArgs);
    await client.signFileEmbeddedStreamWithPrior({
      ...signArgs,
      operationId: "op-embedded-revision",
      priorFilePath: "/tmp/prior.signed.mov",
    });
    await client.signFileDetachedStreamWithPrior({
      ...detachedArgs,
      operationId: "op-detached-revision",
      priorFilePath: "/tmp/prior.mov",
    });
    await client.verifyFileEmbeddedStream(verifyArgs);
    await client.verifyFileDetachedStream(detachedVerifyArgs);
    await client.cancelStream("op-embedded");

    expect(transport.calls.filter((call) => call.command !== "open_session")).toEqual([
      { command: "sign_file_embedded_stream", args: { args: signArgs } },
      { command: "sign_file_detached_stream", args: { args: detachedArgs } },
      {
        command: "sign_file_embedded_stream_with_prior",
        args: { args: { ...signArgs, operationId: "op-embedded-revision", priorFilePath: "/tmp/prior.signed.mov" } },
      },
      {
        command: "sign_file_detached_stream_with_prior",
        args: { args: { ...detachedArgs, operationId: "op-detached-revision", priorFilePath: "/tmp/prior.mov" } },
      },
      { command: "verify_file_embedded_stream", args: { args: verifyArgs } },
      { command: "verify_file_detached_stream", args: { args: detachedVerifyArgs } },
      { command: "cancel_stream", args: { operationId: "op-embedded" } },
    ]);

    await client.dispose();
  });

  it("exposes native system profile and adaptive streaming recommendations", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });

    await client.getSystemProfile();
    await client.getRecommendedStreamingConfig();

    expect(transport.calls.filter((call) => call.command !== "open_session")).toEqual([
      { command: "get_system_profile", args: undefined },
      { command: "get_recommended_streaming_config", args: undefined },
    ]);

    await client.signFileEmbeddedStream({
      operationId: "op-auto",
      inputPath: "/tmp/source.mov",
      outputPath: "/tmp/signed.mov",
      streaming: { chunkSize: null },
    });

    expect(transport.calls.at(-1)).toEqual({
      command: "sign_file_embedded_stream",
      args: {
        args: {
          operationId: "op-auto",
          inputPath: "/tmp/source.mov",
          outputPath: "/tmp/signed.mov",
          streaming: { chunkSize: null },
        },
      },
    });

    await client.dispose();
  });

  it("subscribes to progress on its dedicated channel without refreshing the read-model", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });
    const listener = vi.fn();
    const unsubscribe = client.onStreamProgress(listener);
    const payload = {
      operationId: "long-video",
      bytesProcessed: 8 * 1024 * 1024,
      totalBytes: 2 * 1024 * 1024 * 1024,
    };

    expect(transport.activeListeners(SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL)).toBe(1);
    expect(transport.activeListeners(SIGNATURE_EVENT_CHANNEL)).toBe(1);

    transport.emit(SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL, {
      type: "stream-progress",
      payload,
    });

    expect(listener).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledWith(payload);
    expect(transport.count("get_snapshot")).toBe(0);

    unsubscribe();
    await client.dispose();
    expect(transport.activeListeners(SIGNATURE_STREAM_PROGRESS_EVENT_CHANNEL)).toBe(0);
    expect(transport.activeListeners(SIGNATURE_EVENT_CHANNEL)).toBe(0);
  });

  it("maps native streaming batch sign and trusted MJKSMAP verify to Rust IPC commands", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });
    const inputs = [
      { manifestPath: "contracts/nda.pdf", sourcePath: "/data/contracts/nda.pdf" },
      { manifestPath: "media/demo.mov", sourcePath: "/data/media/demo.mov" },
    ];

    await client.signBatchDetachedPathsStream({
      operationId: "batch-sign-1",
      inputs,
      mapOutputPath: "/data/output/contracts.mjksmap",
      options: { mode: "map", continueOnError: true },
      streaming: { chunkSize: 4 * 1024 * 1024, maxBytesPerFile: 10 * 1024 * 1024 * 1024 },
    });
    await client.verifyMjksMapPathsStream({
      operationId: "batch-verify-1",
      mapPath: "/data/output/contracts.mjksmap",
      inputs,
      target: { accountId: "local-account" },
      streaming: { chunkSize: 2 * 1024 * 1024 },
    });

    expect(transport.calls.filter((call) => call.command !== "open_session")).toEqual([
      {
        command: "sign_batch_detached_paths_stream",
        args: {
          args: {
            operationId: "batch-sign-1",
            inputs,
            mapOutputPath: "/data/output/contracts.mjksmap",
            options: { mode: "map", continueOnError: true },
            streaming: { chunkSize: 4 * 1024 * 1024, maxBytesPerFile: 10 * 1024 * 1024 * 1024 },
          },
        },
      },
      {
        command: "verify_mjks_map_paths_stream",
        args: {
          args: {
            operationId: "batch-verify-1",
            mapPath: "/data/output/contracts.mjksmap",
            inputs,
            target: { accountId: "local-account" },
            streaming: { chunkSize: 2 * 1024 * 1024 },
          },
        },
      },
    ]);
    await client.dispose();
  });

  it("rejects malicious and excessive native streaming input before IPC", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });
    const callsAfterOpen = transport.calls.length;

    expect(() => client.signFileEmbeddedStream({
      operationId: "bad\nid",
      inputPath: "/tmp/source.pdf",
      outputPath: "/tmp/signed.pdf",
    })).toThrow();

    expect(() => client.signFileEmbeddedStream({
      operationId: "chunk-too-large",
      inputPath: "/tmp/source.pdf",
      outputPath: "/tmp/signed.pdf",
      streaming: { chunkSize: 64 * 1024 * 1024 + 1 },
    })).toThrow();

    expect(() => client.signBatchDetachedPathsStream({
      operationId: "path-traversal",
      inputs: [{ manifestPath: "safe/../escape.pdf", sourcePath: "/tmp/source.pdf" }],
      mapOutputPath: "/tmp/map.mjksmap",
    })).toThrow();

    expect(() => client.signBatchDetachedPathsStream({
      operationId: "duplicate-alias",
      inputs: [
        { manifestPath: "folder/file.pdf", sourcePath: "/tmp/a.pdf" },
        { manifestPath: "folder\\file.pdf", sourcePath: "/tmp/b.pdf" },
      ],
      mapOutputPath: "/tmp/map.mjksmap",
    })).toThrow();

    expect(() => client.signBatchDetachedPathsStream({
      operationId: "too-many",
      inputs: Array.from({ length: 10_001 }, (_, index) => ({
        manifestPath: "file-" + index + ".pdf",
        sourcePath: "/tmp/file-" + index + ".pdf",
      })),
      mapOutputPath: "/tmp/map.mjksmap",
    })).toThrow();

    expect(() => client.verifyMjksMapPathsStream({
      operationId: "untrusted-key",
      mapPath: "/tmp/map.mjksmap",
      inputs: [{ manifestPath: "file.pdf", sourcePath: "/tmp/file.pdf" }],
      target: { expectedSignerId: "self-reported-only" },
    })).toThrow();

    expect(() => client.signBatchDetachedPathsStream({
      operationId: "bidi-path",
      inputs: [{ manifestPath: "file\u202e.pdf", sourcePath: "/tmp/file.pdf" }],
      mapOutputPath: "/tmp/map.mjksmap",
    })).toThrow();

    expect(transport.calls).toHaveLength(callsAfterOpen);
    await client.dispose();
  });

  it("accepts the maximum native streaming chunk size and rejects overlong source paths locally", async () => {
    const transport = new FakeTransport();
    const client = await MajikSignatureClientTauri.open({ transport });

    await client.signFileEmbeddedStream({
      operationId: "chunk-max",
      inputPath: "/tmp/source.pdf",
      outputPath: "/tmp/signed.pdf",
      streaming: { chunkSize: 64 * 1024 * 1024 },
    });

    await expect(client.verifyFileEmbeddedStream({
      operationId: "path-too-long",
      inputPath: "x".repeat(4_097),
    })).rejects.toThrow();

    expect(transport.count("sign_file_embedded_stream")).toBe(1);
    expect(transport.count("verify_file_embedded_stream")).toBe(0);
    await client.dispose();
  });


});
