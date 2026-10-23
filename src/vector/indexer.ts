import { createHash } from "node:crypto";
import type { QdrantClient } from "@qdrant/js-client-rest";
import type { DocumentChunk, SearchHit } from "../types.ts";
import { ensureCollection, getCollectionName, qdrantClient } from "./client.ts";
import {
  DENSE_VECTOR_NAME,
  SPARSE_VECTOR_NAME,
  DEFAULT_HASH_DIMENSION,
  dimensionFromEnvironment,
  documentFromPayload,
  payloadFromDocument,
} from "./schema.ts";

export type SparseVector = { indices: number[]; values: number[] };

async function mapConcurrent<T, R>(items: T[], concurrency: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await mapper(items[index]!);
    }
  }));
  return results;
}

export interface VectorStore {
  upsert(documents: DocumentChunk[]): Promise<void>;
  get(ids: string[]): Promise<SearchHit[]>;
  search(query: string, limit: number): Promise<SearchHit[]>;
  delete(ids: string[]): Promise<void>;
  close?(): Promise<void>;
}

export function tokenize(text: string): string[] {
  return (text.toLocaleLowerCase().match(/[\p{L}\p{N}_+#.-]+/gu) ?? [])
    .map((token) => token.replace(/^[.+#-]+|[.+#-]+$/g, ""))
    .filter((token) => token.length > 1);
}

function hashIndex(token: string): number {
  return createHash("sha256").update(token).digest().readUInt32LE(0) & 0x7fffffff;
}

export function sparseVector(text: string): SparseVector {
  const counts = new Map<number, number>();
  for (const token of tokenize(text)) {
    const index = hashIndex(token);
    counts.set(index, (counts.get(index) ?? 0) + 1);
  }
  const entries = [...counts.entries()].sort(([a], [b]) => a - b);
  return {
    indices: entries.map(([index]) => index),
    values: entries.map(([, count]) => 1 + Math.log(count)),
  };
}

export function hashEmbedText(text: string, dimension = DEFAULT_HASH_DIMENSION): number[] {
  const vector = new Float32Array(dimension);
  for (const token of tokenize(text)) {
    const digest = createHash("sha256").update(token).digest();
    const index = digest.readUInt32LE(0) % dimension;
    const sign = digest[4]! & 1 ? 1 : -1;
    vector[index]! += sign * (1 + Math.log(token.length));
  }
  let magnitude = 0;
  for (const value of vector) magnitude += value * value;
  const norm = Math.sqrt(magnitude) || 1;
  return Array.from(vector, (value) => value / norm);
}

export async function embedText(text: string): Promise<number[]> {
  const dimension = dimensionFromEnvironment();
  if (process.env.EMBEDDING_PROVIDER === "ollama") {
    const baseUrl = (process.env.OLLAMA_URL || "http://127.0.0.1:11434").replace(/\/$/, "");
    const response = await fetch(`${baseUrl}/api/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(Number(process.env.EMBEDDING_TIMEOUT_MS || 30_000)),
      body: JSON.stringify({
        model: process.env.OLLAMA_EMBED_MODEL || "nomic-embed-text",
        input: text,
      }),
    });
    if (!response.ok) throw new Error(`Ollama embedding failed (${response.status}): ${await response.text()}`);
    const result = await response.json() as { embeddings?: number[][]; embedding?: number[] };
    const vector = result.embeddings?.[0] ?? result.embedding;
    if (!vector?.length) throw new Error("Ollama returned no embedding vector");
    if (vector.length !== dimension) {
      throw new Error(`Embedding dimension ${vector.length} does not match VECTOR_DIMENSION=${dimension}`);
    }
    return vector;
  }

  return hashEmbedText(text, dimension);
}

function stableId(key: string): string {
  const hex = createHash("sha256").update(key).digest("hex").slice(0, 32).split("");
  hex[12] = "5";
  hex[16] = ((parseInt(hex[16]!, 16) & 3) | 8).toString(16);
  const raw = hex.join("");
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}

export function documentId(document: DocumentChunk): string {
  const metadata = document.metadata;
  const identity = document.modality === "vulnerability" && metadata.advisoryId
    ? `advisory:${metadata.advisoryId}`
    : document.modality === "code" && metadata.path
      ? `code:${metadata.path}:${metadata.symbol ?? document.title}:${metadata.signature ?? ""}`
      : `${document.source}:${document.title}:${metadata.part ?? ""}`;
  return stableId(`${document.modality}\u0000${identity}`);
}

export class QdrantVectorStore implements VectorStore {
  constructor(private readonly client: QdrantClient = qdrantClient) {}

  async initialize(): Promise<void> {
    await ensureCollection();
  }

  async upsert(documents: DocumentChunk[]): Promise<void> {
    if (documents.length === 0) return;
    const concurrency = Number(process.env.EMBEDDING_CONCURRENCY || 4);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {
      throw new Error("EMBEDDING_CONCURRENCY must be an integer from 1 to 64");
    }
    for (let offset = 0; offset < documents.length; offset += 128) {
      const batch = documents.slice(offset, offset + 128);
      const points = await mapConcurrent(batch, concurrency, async (document) => {
        const text = `${document.title}\n${document.content}`;
        return {
          id: documentId(document),
          vector: {
            [DENSE_VECTOR_NAME]: await embedText(text),
            [SPARSE_VECTOR_NAME]: sparseVector(text),
          },
          payload: payloadFromDocument(document),
        };
      });
      await this.client.upsert(getCollectionName(), { points, wait: true });
    }
  }

  async get(ids: string[]): Promise<SearchHit[]> {
    if (ids.length === 0) return [];
    const points = await this.client.retrieve(getCollectionName(), {
      ids,
      with_payload: true,
      with_vector: false,
    });
    return points.map((point) => ({
      id: String(point.id),
      score: 1,
      document: documentFromPayload(String(point.id), (point.payload ?? {}) as Record<string, unknown>),
    }));
  }

  async delete(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    await this.client.delete(getCollectionName(), { points: ids, wait: true });
  }

  async search(query: string, limit: number): Promise<SearchHit[]> {
    const dense = await embedText(query);
    const sparse = sparseVector(query);
    const response = await this.client.query(getCollectionName(), {
      prefetch: [
        { query: dense, using: DENSE_VECTOR_NAME, limit: Math.max(limit * 3, 12) },
        { query: sparse, using: SPARSE_VECTOR_NAME, limit: Math.max(limit * 3, 12) },
      ],
      query: { fusion: "rrf" },
      limit,
      with_payload: true,
      with_vector: false,
    });
    return response.points.map((point) => ({
      id: String(point.id),
      score: Number(point.score ?? 0),
      document: documentFromPayload(String(point.id), point.payload ?? {}),
    }));
  }
}
