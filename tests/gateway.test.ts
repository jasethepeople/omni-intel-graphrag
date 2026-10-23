import { describe, expect, test } from "bun:test";import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import type { DocumentChunk } from "../src/types.ts";
import { createGatewayHandler } from "../src/core/router.ts";
import type { MediaInput } from "../src/ingestors/media.ts";
import { normalizeAdvisory } from "../src/ingestors/security.ts";
import { InMemoryVectorStore } from "../src/vector/memory.ts";
import { ensureCollection } from "../src/vector/client.ts";
import { documentId, QdrantVectorStore } from "../src/vector/indexer.ts";
import { InMemoryKnowledgeGraph, SQLiteKnowledgeGraph } from "../src/vector/graph.ts";
import { parseCodeFile } from "../src/ingestors/code.ts";

function makeApp(apiKey?: string) {
  const store = new InMemoryVectorStore();
  const graph = new InMemoryKnowledgeGraph();
  const handler = createGatewayHandler({
    store,
    graph,
    apiKey,
    mediaProcessor: async (input: MediaInput): Promise<DocumentChunk[]> => [{
      id: "test-media",
      content: `Transcript from ${input.filename}: ${new TextDecoder().decode(input.bytes)}`,
      title: input.filename,
      source: input.filename,
      modality: "media",
      fileType: input.mimeType,
      tags: ["media", "audio", "transcript"],
      createdAt: new Date().toISOString(),
      metadata: { mediaType: "audio" },
    }],
  });
  return { store, handler };
}

async function post(handler: (request: Request) => Promise<Response>, path: string, body: unknown, apiKey?: string) {
  return handler(new Request(`http://localhost${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
    body: JSON.stringify(body),
  }));
}

describe("Omni-Intel gateway", () => {
  test("indexes AST code and a normalized vulnerability, then returns citation-grounded hybrid retrieval", async () => {
    const { store, handler } = makeApp();
    const codeResponse = await post(handler, "/api/v1/ingest/code", {
      source: "sample-repository",
      files: [{ path: "src/input.ts", content: `import { sanitize } from "./sanitize";\nexport function parseUserInput(value: string): string { return sanitize(value); }` }],
    });
    expect(codeResponse.status).toBe(201);
    const codeResult = await codeResponse.json() as { indexed: number; ids: string[] };
    expect(codeResult.indexed).toBeGreaterThanOrEqual(2);
    expect(codeResult.ids).toHaveLength(codeResult.indexed);

    const securityResponse = await post(handler, "/api/v1/ingest/vulnerability", {
      advisory: {
        id: "GHSA-test-1234",
        aliases: ["CVE-2025-12345"],
        summary: "Unsafe parser allows remote code execution",
        details: "Affected package parser-kit versions below 2.1.0 allow an attacker to execute code using crafted input.",
        database_specific: { severity: "HIGH" },
        affected: [{ package: { ecosystem: "npm", name: "parser-kit" }, versions: ["1.0.0", "2.0.9"] }],
        references: [{ url: "https://example.test/advisory" }],
      },
    });
    expect(securityResponse.status).toBe(201);
    const securityResult = await securityResponse.json() as { indexed: number; ids: string[] };
    expect(securityResult.indexed).toBe(1);
    expect(store.size).toBeGreaterThanOrEqual(3);

    const queryResponse = await post(handler, "/api/v1/query", {
      query: "Which function parses user input, and what vulnerability affects parser-kit?",
      limit: 8,
    });
    expect(queryResponse.status).toBe(200);
    const result = await queryResponse.json() as {
      citations: Array<{ id: string; source: string; graphRelations: string[] }>;
      context: Array<{ citationId: string; title: string; content: string; graphRelations: string[] }>;
      retrievalPlan: Array<{ agent: string; matches: number }>;
    };
    expect(result.retrievalPlan.length).toBeGreaterThan(1);
    expect(result.citations.length).toBeGreaterThan(0);
    expect(result.context.some((chunk) => chunk.content.includes("parseUserInput"))).toBe(true);
    expect(result.context.some((chunk) => chunk.content.includes("parser-kit"))).toBe(true);
    expect(result.citations.every((citation) => citation.source.length > 0)).toBe(true);
    expect(result.context.every((chunk) => result.citations.some((citation) => citation.id === chunk.citationId))).toBe(true);
    expect(result.retrievalPlan.some((step) => step.agent === "graph" && step.matches > 0)).toBe(true);
    expect(result.context.some((chunk) => chunk.graphRelations.length > 0)).toBe(true);
    expect(result.context.some((chunk) => chunk.graphRelations.some((relation) => relation.includes("affects")))).toBe(true);
  });

  test("persists SQLite entity relationships across reopen for exact code symbols", async () => {
    const directory = await mkdtemp(join(import.meta.dir, ".graph-test-"));
    const databasePath = join(directory, "graph.sqlite");
    const documents = parseCodeFile({
      path: "src/validator.ts",
      content: "export function parseUserInput(value: string) { return value.trim(); }",
    }, "graph-test-repository");
    try {
      const graph = new SQLiteKnowledgeGraph(databasePath);
      await graph.upsert(documents);
      graph.close();
      const reopened = new SQLiteKnowledgeGraph(databasePath);
      try {
        const matches = await reopened.search("parseUserInput", 5);
        expect(matches.some((match) => match.documentId === documentId(documents[0]!))).toBe(true);
        expect(matches[0]?.relationPath).toContain("defined_in");
      } finally {
        reopened.close();
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("parses TypeScript module extensions and exported arrow declarations", () => {
    const documents = parseCodeFile({
      path: "src/parser.mts",
      content: "export const parseValue = (value: string): string => value.trim();",
    });
    expect(documents).toHaveLength(1);
    expect(documents[0]?.metadata.symbol).toBe("parseValue");
    expect(documents[0]?.metadata.exported).toBe(true);
    expect(documents[0]?.content).toContain("Signature: (value: string): string =>");
  });

  test("rejects invalid body-size configuration rather than disabling limits", () => {
    expect(() => createGatewayHandler({ store: new InMemoryVectorStore(), jsonLimitBytes: 0 })).toThrow("MAX_JSON_BYTES");
    expect(() => createGatewayHandler({ store: new InMemoryVectorStore(), mediaLimitBytes: Number.NaN })).toThrow("MAX_MEDIA_BYTES");
  });

  test("normalizes severity labels without fabricating a numeric CVSS score", () => {
    const advisory = normalizeAdvisory({
      id: "GHSA-test-1234",
      database_specific: { severity: "HIGH" },
      affected: [{ package: { ecosystem: "npm", name: "parser-kit" }, versions: ["1.0.0"] }],
    });
    expect(advisory.severityLabel).toBe("HIGH");
    expect(advisory.severity).toBeUndefined();
    expect(advisory.affected[0]?.package).toBe("parser-kit");
  });

  test("ingests a root-level advisory with an id without making a feed request", async () => {
    const { store, handler } = makeApp();
    const response = await post(handler, "/api/v1/ingest/vulnerability", {
      id: "CVE-2025-55555",
      source: "NVD",
      descriptions: [{ lang: "en", value: "A directly supplied NVD advisory." }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
    });
    expect(response.status).toBe(201);
    expect(store.size).toBe(1);
    const hits = await store.search("CVE-2025-55555 directly supplied NVD", 2);
    expect(hits[0]?.document.source.startsWith("NVD:")).toBe(true);
  });

  test("syncs a page of the NVD modification feed and returns its pagination cursor", async () => {
    const { store, handler } = makeApp();
    const originalFetch = globalThis.fetch;
    let requestedUrl = "";
    globalThis.fetch = (async (input: string | URL | Request) => {
      requestedUrl = String(input);
      return Response.json({
        totalResults: 2,
        startIndex: 0,
        resultsPerPage: 1,
        vulnerabilities: [{ cve: {
          id: "CVE-2026-80001",
          descriptions: [{ lang: "en", value: "A test vulnerability affects package parser-kit." }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.4, baseSeverity: "HIGH" } }] },
          references: [{ url: "https://nvd.example/CVE-2026-80001" }],
        } }],
      });
    }) as typeof fetch;
    try {
      const tooWide = await post(handler, "/api/v1/ingest/vulnerability", {
        provider: "nvd",
        start: "2026-01-01T00:00:00.000Z",
        end: "2026-06-01T00:00:00.000Z",
      });
      expect(tooWide.status).toBe(400);
      expect(requestedUrl).toBe("");
      const response = await post(handler, "/api/v1/ingest/vulnerability", {
        provider: "nvd",
        start: "2026-10-19T00:00:00.000Z",
        end: "2026-10-20T00:00:00.000Z",
        pageSize: 1,
      });

      expect(response.status).toBe(201);
      const result = await response.json() as { indexed: number; feed: { nextStartIndex: number | null } };
      expect(result.indexed).toBe(1);
      expect(result.feed.nextStartIndex).toBe(1);
      expect(new URL(requestedUrl).searchParams.get("startIndex")).toBe("0");
      expect(store.size).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("protects API routes when a bearer key is configured and caps request bodies", async () => {
    const { handler } = makeApp("test-secret");
    const unauthorized = await post(handler, "/api/v1/query", { query: "secret" });
    expect(unauthorized.status).toBe(401);
    const authorized = await post(handler, "/api/v1/query", { query: "nothing", limit: 2 }, "test-secret");
    expect(authorized.status).toBe(200);
    const tooSmall = createGatewayHandler({ store: new InMemoryVectorStore(), jsonLimitBytes: 10 });
    const oversized = await post(tooSmall, "/api/v1/query", { query: "too large" });
    expect(oversized.status).toBe(413);
  });

  test("accepts media uploads through the local processing adapter", async () => {
    const { store, handler } = makeApp();
    const response = await post(handler, "/api/v1/ingest/media", {
      filename: "meeting.wav",
      mimeType: "audio/wav",
      base64: Buffer.from("the transcript mentions a local security review").toString("base64"),
    });
    expect(response.status).toBe(201);
    const result = await response.json() as { indexed: number; ids: string[] };
    expect(result.indexed).toBe(1);
    expect(result.ids).toHaveLength(1);
    expect(store.size).toBe(1);
  });

  test("serves health through Bun's native HTTP listener", async () => {
    const { handler } = makeApp();
    const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: handler });
    try {
      const response = await fetch(`http://127.0.0.1:${server.port}/health`);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ status: "ok", service: "omni-intel-graphrag" });
    } finally {
      server.stop(true);
    }
  });

  test.skipIf(process.env.QDRANT_INTEGRATION !== "1")("runs against a real Qdrant collection when explicitly enabled", async () => {
    await ensureCollection();
    const store = new QdrantVectorStore();
    const document: DocumentChunk = {
      id: `integration-${crypto.randomUUID()}`,
      content: "Integration sentinel advisory package for local Qdrant hybrid test",
      title: "Qdrant integration sentinel",
      source: "integration-test",
      modality: "vulnerability",
      fileType: "security-advisory",
      tags: ["integration"],
      severity: 5,
      createdAt: new Date().toISOString(),
      metadata: { integration: true },
    };
    const id = documentId(document);
    try {
      await store.upsert([document]);
      const hits = await store.search("integration sentinel advisory", 10);
      expect(hits.some((hit) => hit.id === id)).toBe(true);
    } finally {
      await store.delete([id]);
    }
  });
});
