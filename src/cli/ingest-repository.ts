import { parseRepository } from "../ingestors/code.ts";
import { QdrantVectorStore } from "../vector/indexer.ts";
import { SQLiteKnowledgeGraph } from "../vector/graph.ts";

const root = process.argv[2];
if (!root) {
  console.error("Usage: bun run ingest:repo -- <repository-directory>");
  process.exit(2);
}

try {
  const documents = await parseRepository(root);
  const store = new QdrantVectorStore();
  await store.initialize();
  await store.upsert(documents);
  const graph = new SQLiteKnowledgeGraph();
  await graph.upsert(documents);
  graph.close();
  console.log(JSON.stringify({ repository: root, indexed: documents.length }, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
