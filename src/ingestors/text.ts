import { createHash } from "node:crypto";
import type { DocumentChunk, Modality } from "../types.ts";

export function splitText(text: string, maxChars = 3500): string[] {
  const normalized = text.trim();
  if (!normalized) return [];
  const chunks: string[] = [];
  let offset = 0;
  while (offset < normalized.length) {
    let end = Math.min(offset + maxChars, normalized.length);
    if (end < normalized.length) {
      const boundary = Math.max(
        normalized.lastIndexOf("\n", end),
        normalized.lastIndexOf(" ", end),
        normalized.lastIndexOf("\t", end),
      );
      if (boundary > offset + Math.floor(maxChars * 0.55)) end = boundary;
    }
    const piece = normalized.slice(offset, end).trim();
    if (piece) chunks.push(piece);
    offset = end;
    while (/\s/.test(normalized[offset] ?? "")) offset++;
  }
  return chunks;
}

export function textDocument(input: { title: string; content: string; source?: string; modality?: Modality; tags?: string[] }): DocumentChunk[] {
  const chunks = splitText(input.content);
  return chunks.map((piece, index) => ({
    id: createHash("sha256").update(`${input.source ?? input.title}:${index}:${piece}`).digest("hex").slice(0, 20),
    title: chunks.length > 1 ? `${input.title} — part ${index + 1}` : input.title,
    content: piece,
    source: input.source ?? input.title,
    modality: input.modality ?? "text",
    fileType: "text/markdown",
    tags: input.tags ?? ["text"],
    createdAt: new Date().toISOString(),
    metadata: { part: index + 1, parts: chunks.length },
  }));
}
