import { timingSafeEqual } from "node:crypto";
import { advisoryToDocument, fetchNvdAdvisory, fetchNvdAdvisoryPage, fetchOsvAdvisory, fetchOsvPackageAdvisories } from "../ingestors/security.ts";
import { parseCodeFile, type CodeInputFile } from "../ingestors/code.ts";
import { processMedia, type MediaInput } from "../ingestors/media.ts";
import { documentId, type VectorStore } from "../vector/indexer.ts";
import { runRetrievalAgent } from "./agent-loop.ts";
import { textDocument } from "../ingestors/text.ts";
import type { DocumentChunk } from "../types.ts";
import type { KnowledgeGraph } from "../vector/graph.ts";

export type GatewayOptions = {
  store: VectorStore;
  apiKey?: string;
  jsonLimitBytes?: number;
  mediaLimitBytes?: number;
  mediaProcessor?: (input: MediaInput) => Promise<DocumentChunk[]>;
  graph?: KnowledgeGraph;
};

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: { "cache-control": "no-store" } });
}

function secureEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function readLimited(request: Request, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > maxBytes) throw new HttpError(413, `Request body exceeds ${maxBytes} bytes`);
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, `Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function readJson(request: Request, maxBytes: number): Promise<Record<string, unknown>> {
  const bytes = await readLimited(request, maxBytes);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "Request body must be a JSON object");
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) throw new HttpError(400, `${name} is required`);
  return value;
}

async function upstream<T>(label: string, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    console.error(`${label} request failed:`, error);
    throw new HttpError(502, `${label} request failed`);
  }
}

async function multipartMedia(request: Request, maxBytes: number): Promise<{ filename: string; mimeType: string; bytes: Uint8Array }> {
  const bytes = await readLimited(request, maxBytes);
  try {
    const clone = new Request(request.url, { method: "POST", headers: request.headers, body: bytes });
    const form = await clone.formData();
    const file = form.get("file");
    if (!(file instanceof File)) throw new HttpError(400, "Multipart request requires a 'file' field");
    return { filename: file.name, mimeType: file.type || "application/octet-stream", bytes: new Uint8Array(await file.arrayBuffer()) };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "Invalid multipart media upload");
  }
}

function base64Media(body: Record<string, unknown>, maxBytes: number): { filename: string; mimeType: string; bytes: Uint8Array } {
  const filename = requiredString(body.filename, "filename");
  const mimeType = requiredString(body.mimeType, "mimeType");
  const encoded = requiredString(body.base64, "base64");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new HttpError(400, "base64 must be a valid padded base64 string");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length > maxBytes) throw new HttpError(413, `Media exceeds ${maxBytes} bytes`);
  return { filename, mimeType, bytes };
}

function ingestResponse(documents: DocumentChunk[]): { indexed: number; ids: string[] } {
  return { indexed: documents.length, ids: documents.map(documentId) };
}

async function indexDocuments(options: GatewayOptions, documents: DocumentChunk[]): Promise<void> {
  await options.store.upsert(documents);
  await options.graph?.upsert(documents);
}

export function createGatewayHandler(options: GatewayOptions): (request: Request) => Promise<Response> {
  const jsonLimit = options.jsonLimitBytes ?? Number(process.env.MAX_JSON_BYTES || 5_000_000);
  const mediaLimit = options.mediaLimitBytes ?? Number(process.env.MAX_MEDIA_BYTES || 52_428_800);
  if (!Number.isSafeInteger(jsonLimit) || jsonLimit < 1) throw new Error("MAX_JSON_BYTES must be a positive safe integer");
  if (!Number.isSafeInteger(mediaLimit) || mediaLimit < 1) throw new Error("MAX_MEDIA_BYTES must be a positive safe integer");

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return json({ status: "ok", service: "omni-intel-graphrag" });
    if (url.pathname.startsWith("/api/") && options.apiKey) {
      const authorization = request.headers.get("authorization") ?? "";
      if (!authorization.startsWith("Bearer ") || !secureEquals(authorization.slice(7), options.apiKey)) {
        return json({ error: "Unauthorized" }, 401);
      }
    }
    if (request.method !== "POST") return json({ error: "Not found" }, 404);

    try {
      if (url.pathname === "/api/v1/ingest/code") {
        const body = await readJson(request, jsonLimit);
        let files: CodeInputFile[];
        if (Array.isArray(body.files)) {
          files = body.files.map((value, index) => {
            if (!value || typeof value !== "object") throw new HttpError(400, `files[${index}] must be an object`);
            const file = value as Record<string, unknown>;
            return { path: requiredString(file.path, `files[${index}].path`), content: requiredString(file.content, `files[${index}].content`) };
          });
        } else if (typeof body.content === "string" && body.content.length) {
          files = [{ path: typeof body.path === "string" ? body.path : "snippet.ts", content: body.content }];
        } else {
          throw new HttpError(400, "Provide a non-empty 'files' array or 'content' string");
        }
        if (files.length > 500) throw new HttpError(413, "A request can contain at most 500 code files");
        const source = typeof body.source === "string" && body.source.trim() ? body.source : undefined;
        const documents = files.flatMap((file) => parseCodeFile(file, source ?? file.path));
        await indexDocuments(options, documents);
        return json(ingestResponse(documents), 201);
      }

      if (url.pathname === "/api/v1/ingest/text") {
        const body = await readJson(request, jsonLimit);
        const title = requiredString(body.title, "title");
        const content = requiredString(body.content, "content");
        const source = typeof body.source === "string" && body.source.trim() ? body.source : title;
        const tags = Array.isArray(body.tags)
          ? body.tags.filter((tag): tag is string => typeof tag === "string").slice(0, 50).map((tag) => tag.slice(0, 120))
          : ["text"];
        const documents = textDocument({ title, content, source, tags });
        if (documents.length === 0) throw new HttpError(400, "content must not be empty");
        await indexDocuments(options, documents);
        return json(ingestResponse(documents), 201);
      }

      if (url.pathname === "/api/v1/ingest/vulnerability") {
        const body = await readJson(request, jsonLimit);
        let advisories: unknown[];
        let feed: Record<string, unknown> | undefined;
        if (body.fetch === true && typeof body.id === "string" && body.id.trim()) {
          if (body.provider !== undefined && body.provider !== "nvd" && body.provider !== "osv") throw new HttpError(400, "provider must be 'nvd' or 'osv'");
          const provider = body.provider === "nvd" ? "nvd" : "osv";
          const advisory = await upstream("Advisory lookup", () => provider === "nvd" ? fetchNvdAdvisory(body.id as string) : fetchOsvAdvisory(body.id as string));
          advisories = [advisory];
        } else if (body.provider === "nvd" && typeof body.start === "string" && typeof body.end === "string") {
          const start = requiredString(body.start, "start");
          const end = requiredString(body.end, "end");
          const startDate = new Date(start);
          const endDate = new Date(end);
          if (!Number.isFinite(startDate.getTime()) || !Number.isFinite(endDate.getTime()) || startDate >= endDate) {
            throw new HttpError(400, "start and end must be valid dates with start before end");
          }
          if (endDate.getTime() - startDate.getTime() > 120 * 24 * 60 * 60 * 1000) {
            throw new HttpError(400, "NVD date windows cannot exceed 120 days");
          }

          const startIndex = body.startIndex === undefined ? 0 : Number(body.startIndex);
          const pageSize = body.pageSize === undefined ? 250 : Number(body.pageSize);
          if (!Number.isInteger(startIndex) || startIndex < 0) throw new HttpError(400, "startIndex must be a non-negative integer");
          if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 500) throw new HttpError(400, "pageSize must be from 1 to 500");
          const page = await upstream("NVD feed", () => fetchNvdAdvisoryPage({ start, end, startIndex, pageSize }));
          advisories = page.advisories;
          feed = {
            provider: "nvd",
            totalResults: page.totalResults,
            startIndex: page.startIndex,
            resultsPerPage: page.resultsPerPage,
            nextStartIndex: page.startIndex + page.resultsPerPage < page.totalResults ? page.startIndex + page.resultsPerPage : null,
          };
        } else if (body.provider === "osv" && typeof body.ecosystem === "string" && typeof body.packageName === "string") {
          const ecosystem = requiredString(body.ecosystem, "ecosystem");
          const packageName = requiredString(body.packageName, "packageName");
          advisories = await upstream("OSV package query", () => fetchOsvPackageAdvisories(ecosystem, packageName));
          feed = { provider: "osv", ecosystem, packageName, totalResults: advisories.length };
        } else if (Array.isArray(body.advisories)) {
          advisories = body.advisories;
        } else {
          advisories = [body.advisory ?? body];
        }
        if (advisories.length > 500) throw new HttpError(413, "A request can contain at most 500 advisories");
        let documents: DocumentChunk[];
        try {
          documents = advisories.map(advisoryToDocument);
        } catch (error) {
          throw new HttpError(400, error instanceof Error ? error.message : "Invalid advisory payload");
        }
        await indexDocuments(options, documents);
        return json({ ...ingestResponse(documents), ...(feed ? { feed } : {}) }, 201);
      }

      if (url.pathname === "/api/v1/ingest/media") {
        const contentType = request.headers.get("content-type") ?? "";
        const media = contentType.toLowerCase().startsWith("multipart/form-data")
          ? await multipartMedia(request, mediaLimit)
          : base64Media(await readJson(request, mediaLimit), mediaLimit);
        const documents = await (options.mediaProcessor ?? processMedia)(media);
        await indexDocuments(options, documents);
        return json(ingestResponse(documents), 201);
      }

      if (url.pathname === "/api/v1/query") {
        const body = await readJson(request, jsonLimit);
        const query = requiredString(body.query, "query");
        const limit = body.limit === undefined ? 8 : Number(body.limit);
        if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new HttpError(400, "limit must be an integer from 1 to 20");
        return json(await runRetrievalAgent(options.store, query, limit, options.graph));
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.error("Gateway request failed:", error);
      return json({ error: "Internal server error" }, 500);
    }
  };
}
