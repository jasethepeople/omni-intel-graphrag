import type { DocumentChunk, SearchHit } from "../types.ts";
import { hashEmbedText, sparseVector, tokenize, type VectorStore } from "./indexer.ts";
import { documentId } from "./indexer.ts";

type IndexedDocument = {
  id: string;
  document: DocumentChunk;
  dense: number[];
  sparse: Map<number, number>;
};

function dot(a: number[], b: number[]): number {
  let score = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) score += a[i]! * b[i]!;
  return score;
}

function sparseMap(indices: number[], values: number[]): Map<number, number> {
  return new Map(indices.map((index, i) => [index, values[i] ?? 0]));
}

export class InMemoryVectorStore implements VectorStore {
  private readonly documents = new Map<string, IndexedDocument>();

  get size(): number {
    return this.documents.size;
  }

  async upsert(documents: DocumentChunk[]): Promise<void> {
    const indexed = await Promise.all(documents.map(async (document) => {
      const text = `${document.title}\n${document.content}`;
      const vector = sparseVector(text);
      const id = documentId(document);
      return [id, { id, document, dense: hashEmbedText(text), sparse: sparseMap(vector.indices, vector.values) }] as const;
    }));
    for (const [id, row] of indexed) this.documents.set(id, row);
  }

  async get(ids: string[]): Promise<SearchHit[]> {
    const requested = new Set(ids);
    return [...this.documents.values()]
      .filter((row) => requested.has(row.id))
      .map((row) => ({ id: row.id, score: 1, document: row.document }));
  }

  async delete(ids: string[]): Promise<void> {
    for (const id of ids) this.documents.delete(id);
  }

  async search(query: string, limit: number): Promise<SearchHit[]> {
    const denseQuery = hashEmbedText(query);
    const sparseQuery = sparseVector(query);
    const querySparse = sparseMap(sparseQuery.indices, sparseQuery.values);
    const queryTokens = new Set(tokenize(query));
    return [...this.documents.values()]
      .map((row) => {
        let lexical = 0;
        for (const [index, value] of querySparse) lexical += value * (row.sparse.get(index) ?? 0);
        const text = `${row.document.title}\n${row.document.content}`.toLocaleLowerCase();
        const tokenBoost = [...queryTokens].reduce((total, token) => total + (text.includes(token) ? 0.08 : 0), 0);
        const denseScore = dot(denseQuery, row.dense);
        const score = 0.55 * denseScore + 0.45 * lexical / (1 + lexical) + tokenBoost;
        return { id: row.id, score, document: row.document };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }
}
