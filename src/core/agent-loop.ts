import type { SearchHit } from "../types.ts";
import type { KnowledgeGraph } from "../vector/graph.ts";
import type { VectorStore } from "../vector/indexer.ts";

export type GroundedQueryResult = {
  query: string;
  answer: string;
  retrievalPlan: Array<{ agent: string; query: string; matches: number }>;
  citations: Array<{ id: string; source: string; title: string; modality: string; score: number; graphRelations: string[] }>;
  context: Array<{ citationId: string; source: string; title: string; content: string; modality: string; score: number; graphRelations: string[] }>;
};

export function decomposeQuery(query: string): Array<{ agent: string; query: string }> {
  const clauses = query
    .split(/(?:\n|[;?]|\.(?:\s|$)|\b(?:and also|additionally)\b)/i)
    .map((part) => part.trim())
    .filter((part) => part.length >= 8);
  const plan = [{ agent: "general", query: query.trim() }];
  for (const clause of clauses) {
    if (clause.toLowerCase() !== query.trim().toLowerCase() && !plan.some((item) => item.query.toLowerCase() === clause.toLowerCase())) {
      plan.push({ agent: "focused", query: clause });
    }
  }
  const lower = query.toLowerCase();
  if (/(cve|vulnerab|advisory|security|exploit|severity)/.test(lower)) {
    plan.push({ agent: "security", query: `${query} affected package severity remediation` });
  }
  if (/(function|method|class|dependency|import|source code|repository)/.test(lower)) {
    plan.push({ agent: "code", query: `${query} function signature dependencies implementation` });
  }
  return plan.slice(0, 5);
}

export async function runRetrievalAgent(
  store: VectorStore,
  query: string,
  limit = 8,
  graph?: KnowledgeGraph,
): Promise<GroundedQueryResult> {
  const normalized = query.trim();
  if (!normalized) throw new Error("Query must not be empty");
  const boundedLimit = Math.min(20, Math.max(1, Math.floor(limit)));
  const plan = decomposeQuery(normalized);
  const [results, graphMatches] = await Promise.all([
    Promise.all(plan.map(async (step) => ({
      ...step,
      hits: await store.search(step.query, Math.min(20, boundedLimit * 2)),
    }))),
    graph ? graph.search(normalized, boundedLimit * 3) : Promise.resolve([]),
  ]);
  const graphHits = graph ? await store.get(graphMatches.map((match) => match.documentId)) : [];
  const graphByDocument = new Map<string, string[]>();
  for (const match of graphMatches) {
    const relations = graphByDocument.get(match.documentId) ?? [];
    if (!relations.includes(match.relationPath)) relations.push(match.relationPath);
    graphByDocument.set(match.documentId, relations);
  }

  const combined = new Map<string, SearchHit & { votes: number; graphRelations: string[] }>();
  for (const result of results) {
    result.hits.forEach((hit, rank) => {
      if (!hit.document.content.trim() || !hit.document.source.trim()) return;
      const current = combined.get(hit.id);
      if (current) {
        current.votes += 1 / (60 + rank + 1);
        current.score = Math.max(current.score, hit.score);
      } else {
        combined.set(hit.id, { ...hit, votes: 1 / (60 + rank + 1), graphRelations: [] });
      }
    });
  }
  graphHits.forEach((hit, rank) => {
    if (!hit.document.content.trim() || !hit.document.source.trim()) return;
    const relations = graphByDocument.get(hit.id) ?? [];
    const current = combined.get(hit.id);
    if (current) {
      current.votes += 0.02 + 1 / (60 + rank + 1);
      current.graphRelations = relations;
    } else {
      combined.set(hit.id, { ...hit, votes: 0.02 + 1 / (60 + rank + 1), graphRelations: relations });
    }
  });

  const ranked = [...combined.values()]
    .sort((a, b) => b.votes - a.votes || b.score - a.score)
    .slice(0, boundedLimit);
  const retrievedIds = new Set([...results.flatMap((result) => result.hits.map((hit) => hit.id)), ...graphHits.map((hit) => hit.id)]);
  const citations = ranked
    .filter((hit) => retrievedIds.has(hit.id) && hit.document.content.trim() && hit.document.source.trim())
    .map((hit) => ({
      id: hit.id,
      source: hit.document.source,
      title: hit.document.title,
      modality: hit.document.modality,
      score: Number(hit.score.toFixed(6)),
      graphRelations: hit.graphRelations,
    }));
  const context = ranked
    .filter((hit) => citations.some((citation) => citation.id === hit.id))
    .map((hit) => ({
      citationId: hit.id,
      source: hit.document.source,
      title: hit.document.title,
      content: hit.document.content,
      modality: hit.document.modality,
      score: Number(hit.score.toFixed(6)),
      graphRelations: hit.graphRelations,
    }));
  const retrievalPlan = results.map(({ agent, query: plannedQuery, hits }) => ({ agent, query: plannedQuery, matches: hits.length }));
  if (graph) retrievalPlan.push({ agent: "graph", query: normalized, matches: graphMatches.length });

  return {
    query: normalized,
    answer: citations.length
      ? "Evidence is retrieved and citation-checked below. Pass the context and citations to a downstream language model to draft a response."
      : "No matching evidence was found in the indexed corpus.",
    retrievalPlan,
    citations,
    context,
  };
}
