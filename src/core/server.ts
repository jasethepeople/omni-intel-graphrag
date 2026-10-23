import { createGatewayHandler } from "./router.ts";
import { SQLiteKnowledgeGraph } from "../vector/graph.ts";
import { QdrantVectorStore } from "../vector/indexer.ts";

export async function startServer(): Promise<void> {
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 8080);
  const loopbackHosts = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PORT must be an integer between 1 and 65535");
  if (!loopbackHosts.has(host) && !process.env.API_KEY) {
    throw new Error("API_KEY is required when binding beyond localhost");
  }
  const store = new QdrantVectorStore();
  await store.initialize();
  const graph = new SQLiteKnowledgeGraph();
  const server = Bun.serve({
    hostname: host,
    port,
    fetch: createGatewayHandler({ store, graph, apiKey: process.env.API_KEY }),
  });
  console.log(`Omni-Intel GraphRAG listening on http://${host}:${server.port}`);
}

if (import.meta.main) {
  startServer().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
