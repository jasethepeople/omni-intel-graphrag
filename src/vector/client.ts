import { QdrantClient } from "@qdrant/js-client-rest";
import { DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME, dimensionFromEnvironment } from "./schema.ts";

const collectionName = process.env.QDRANT_COLLECTION || "omni_intel";

export const qdrantClient = new QdrantClient({
  url: process.env.QDRANT_URL || "http://127.0.0.1:6333",
  apiKey: process.env.QDRANT_API_KEY || undefined,
  timeout: Number(process.env.QDRANT_TIMEOUT_MS || 10_000),
  maxConnections: Number(process.env.QDRANT_MAX_CONNECTIONS || 32),
  checkCompatibility: false,
});

export async function ensureCollection(): Promise<void> {
  const exists = await qdrantClient.collectionExists(collectionName);
  if (!exists.exists) {
    await qdrantClient.createCollection(collectionName, {
      vectors: {
        [DENSE_VECTOR_NAME]: { size: dimensionFromEnvironment(), distance: "Cosine" },
      },
      sparse_vectors: {
        [SPARSE_VECTOR_NAME]: { index: { on_disk: false } },
      },
      on_disk_payload: true,
    });
  }

  else {
    const info = await qdrantClient.getCollection(collectionName);
    const params = info.config.params as unknown as {
      vectors?: Record<string, { size?: number }>;
      sparse_vectors?: Record<string, unknown>;
    };
    const dense = params.vectors?.[DENSE_VECTOR_NAME];
    if (!dense || dense.size !== dimensionFromEnvironment()) {
      throw new Error(`Qdrant collection '${collectionName}' must have a '${DENSE_VECTOR_NAME}' vector of size ${dimensionFromEnvironment()}`);
    }
    if (!params.sparse_vectors?.[SPARSE_VECTOR_NAME]) {
      throw new Error(`Qdrant collection '${collectionName}' must define the '${SPARSE_VECTOR_NAME}' sparse vector`);
    }
  }

  for (const field_name of ["source", "modality", "fileType", "tags"]) {
    try {
      await qdrantClient.createPayloadIndex(collectionName, {
        field_name,
        field_schema: "keyword",
        wait: true,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!/already exists|index already exists/i.test(message)) throw error;
    }
  }
}

export function getCollectionName(): string {
  return collectionName;
}
