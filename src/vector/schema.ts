import type { DocumentChunk } from "../types.ts";

export const DENSE_VECTOR_NAME = "dense";
export const SPARSE_VECTOR_NAME = "sparse";
export const DEFAULT_HASH_DIMENSION = 384;
export const DEFAULT_OLLAMA_DIMENSION = 768;

export function dimensionFromEnvironment(): number {
  const explicit = Number(process.env.VECTOR_DIMENSION);
  if (Number.isInteger(explicit) && explicit > 0) return explicit;
  return process.env.EMBEDDING_PROVIDER === "ollama"
    ? DEFAULT_OLLAMA_DIMENSION
    : DEFAULT_HASH_DIMENSION;
}

export function payloadFromDocument(document: DocumentChunk): Record<string, unknown> {
  return {
    title: document.title,
    content: document.content,
    source: document.source,
    modality: document.modality,
    fileType: document.fileType,
    tags: document.tags,
    severity: document.severity ?? null,
    createdAt: document.createdAt,
    metadata: document.metadata,
  };
}

export function documentFromPayload(id: string, payload: Record<string, unknown>): DocumentChunk {
  return {
    id,
    title: String(payload.title ?? "Untitled"),
    content: String(payload.content ?? ""),
    source: String(payload.source ?? "unknown"),
    modality: (payload.modality as DocumentChunk["modality"]) ?? "text",
    fileType: String(payload.fileType ?? "text/plain"),
    tags: Array.isArray(payload.tags) ? payload.tags.map(String) : [],
    severity: typeof payload.severity === "number" ? payload.severity : undefined,
    createdAt: String(payload.createdAt ?? new Date(0).toISOString()),
    metadata: payload.metadata && typeof payload.metadata === "object"
      ? payload.metadata as Record<string, unknown>
      : {},
  };
}
