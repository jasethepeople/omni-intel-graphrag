import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Database } from "bun:sqlite";
import type { DocumentChunk } from "../types.ts";
import { documentId, tokenize } from "./indexer.ts";

export type GraphMatch = {
  documentId: string;
  matchedEntity: string;
  relationPath: string;
  score: number;
};

export interface KnowledgeGraph {
  upsert(documents: DocumentChunk[]): Promise<void>;
  search(query: string, limit: number): Promise<GraphMatch[]>;
  close?(): void;
}

type Entity = { id: string; kind: string; name: string };
type Relation = { from: Entity; relation: string; to: Entity };

function normalized(value: string): string {
  return value.trim().toLocaleLowerCase().replace(/\\/g, "/");
}

function entity(kind: string, name: string): Entity {
  const clean = name.trim().slice(0, 500);
  return { id: `${kind}:${normalized(clean)}`, kind, name: clean };
}

function createRelations(document: DocumentChunk, pointId: string): Relation[] {
  const doc = entity("document", pointId);
  const relations: Relation[] = [];
  const seen = new Set<string>();
  const add = (from: Entity, relation: string, to: Entity): void => {
    const key = `${from.id}\\0${relation}\\0${to.id}`;
    if (from.id === to.id || seen.has(key)) return;
    seen.add(key);
    relations.push({ from, relation, to });
  };
  const addMention = (kind: string, name: unknown, relation = "mentions"): Entity | undefined => {
    if (typeof name !== "string" || !name.trim()) return;
    const value = entity(kind, name);
    add(doc, relation, value);
    return value;
  };

  addMention("source", document.source);
  if (document.modality === "code") {
    const file = addMention("file", document.metadata.path ?? document.title, "in_file");
    const symbol = addMention("symbol", document.metadata.symbol, "defines");
    if (file && symbol) add(symbol, "defined_in", file);
    if (Array.isArray(document.metadata.dependencies)) {
      for (const dependency of document.metadata.dependencies) {
        const dependencyEntity = addMention("dependency", dependency);
        if (symbol && dependencyEntity) add(symbol, "depends_on", dependencyEntity);
      }
    }
    if (Array.isArray(document.metadata.imports)) {
      for (const dependency of document.metadata.imports) addMention("dependency", dependency);
    }
  }

  if (document.modality === "vulnerability") {
    const advisory = addMention("advisory", document.metadata.advisoryId, "describes");
    if (Array.isArray(document.metadata.aliases)) {
      for (const alias of document.metadata.aliases) {
        const aliasEntity = addMention("alias", alias);
        if (advisory && aliasEntity) add(advisory, "alias_of", aliasEntity);
      }
    }
    if (Array.isArray(document.metadata.affected)) {
      for (const affected of document.metadata.affected) {
        if (!affected || typeof affected !== "object") continue;
        const row = affected as Record<string, unknown>;
        const packageName = typeof row.package === "string" ? row.package : undefined;
        const ecosystem = typeof row.ecosystem === "string" ? row.ecosystem : undefined;
        const packageEntity = packageName ? addMention("package", packageName) : undefined;
        const ecosystemPackage = ecosystem && packageName ? addMention("package", `${ecosystem}/${packageName}`) : undefined;
        if (advisory && packageEntity) add(advisory, "affects", packageEntity);
        if (advisory && ecosystemPackage) add(advisory, "affects", ecosystemPackage);
        if (packageEntity && Array.isArray(row.versions)) {
          for (const version of row.versions) {
            if (typeof version !== "string" || !version.trim()) continue;
            const versionEntity = entity("version", version);
            add(doc, "mentions", versionEntity);
            add(packageEntity, "has_version_range", versionEntity);
          }
        }
      }
    }
    if (typeof document.metadata.severityLabel === "string") addMention("severity", document.metadata.severityLabel);
  }

  for (const tag of document.tags) {
    if (tag.length > 3 && !["security", "vulnerability", "function", "module", "exported", "code", "media", "transcript"].includes(tag.toLowerCase())) {
      addMention("tag", tag);
    }
  }
  return relations;
}

function entityMatches(name: string, terms: Set<string>): boolean {
  const lower = normalized(name);
  return [...terms].some((term) => lower === term || (term.length >= 5 && lower.includes(term)));
}

export class InMemoryKnowledgeGraph implements KnowledgeGraph {
  private readonly nodes = new Map<string, Entity>();
  private readonly edges = new Map<string, Relation>();

  async upsert(documents: DocumentChunk[]): Promise<void> {
    for (const document of documents) {
      const pointId = documentId(document);
      const doc = entity("document", pointId);
      for (const [key, relation] of this.edges) {
        if (relation.from.id === doc.id) this.edges.delete(key);
      }
      const created = createRelations(document, pointId);
      for (const row of created) {
        this.nodes.set(row.from.id, row.from);
        this.nodes.set(row.to.id, row.to);
        this.edges.set(`${row.from.id}\\0${row.relation}\\0${row.to.id}`, row);
      }
    }
  }

  async search(query: string, limit: number): Promise<GraphMatch[]> {
    const terms = new Set(tokenize(query));
    const matches = new Map<string, GraphMatch>();
    const edges = [...this.edges.values()];
    const matchedNodes = [...this.nodes.values()].filter((node) => node.kind !== "document" && entityMatches(node.name, terms));
    for (const matched of matchedNodes) {
      for (const edge of edges) {
        if (edge.from.id !== matched.id && edge.to.id !== matched.id) continue;
        const neighbor = edge.from.id === matched.id ? edge.to : edge.from;
        const paths = neighbor.kind === "document"
          ? [{ documentId: neighbor.name, relationPath: `${matched.name} —${edge.relation}→ document` }]
          : edges.flatMap((link) => {
            if (link.from.id !== neighbor.id && link.to.id !== neighbor.id) return [];
            const documentNode = link.from.kind === "document" ? link.from : link.to.kind === "document" ? link.to : undefined;
            return documentNode ? [{ documentId: documentNode.name, relationPath: `${matched.name} —${edge.relation}→ ${neighbor.name} —${link.relation}→ document` }] : [];
          });
        for (const path of paths) {
          const current = matches.get(path.documentId);
          const score = matched.name.toLowerCase() === [...terms].find((term) => normalized(matched.name) === term) ? 1 : 0.75;
          if (!current || score > current.score || (score === current.score && path.relationPath.length > current.relationPath.length)) {
            matches.set(path.documentId, { ...path, matchedEntity: matched.name, score });
          }
        }
      }
    }
    return [...matches.values()].sort((a, b) => b.score - a.score).slice(0, limit);
  }
}

export class SQLiteKnowledgeGraph implements KnowledgeGraph {
  private readonly database: Database;
  private readonly insertNode;
  private readonly insertEdge;
  private readonly deleteDocumentEdges;
  private readonly searchNodes;
  private readonly adjacentNodes;
  private readonly linkedDocuments;

  constructor(databasePath = process.env.GRAPH_DB_PATH || "./data/knowledge-graph.sqlite") {
    const path = databasePath === ":memory:" ? databasePath : resolve(databasePath);
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.database = new Database(path, { create: true });
    this.database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        name_lc TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS edges (
        from_id TEXT NOT NULL,
        relation TEXT NOT NULL,
        to_id TEXT NOT NULL,
        PRIMARY KEY (from_id, relation, to_id)
      );
      CREATE INDEX IF NOT EXISTS nodes_name_lc_idx ON nodes(name_lc);
      CREATE INDEX IF NOT EXISTS edges_from_idx ON edges(from_id);
      CREATE INDEX IF NOT EXISTS edges_to_idx ON edges(to_id);
    `);
    this.insertNode = this.database.prepare("INSERT INTO nodes (id, kind, name, name_lc) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, name_lc=excluded.name_lc");
    this.insertEdge = this.database.prepare("INSERT OR IGNORE INTO edges (from_id, relation, to_id) VALUES (?, ?, ?)");
    this.deleteDocumentEdges = this.database.prepare("DELETE FROM edges WHERE from_id = ?");
    this.searchNodes = this.database.prepare("SELECT id, kind, name FROM nodes WHERE name_lc = ? OR (name_lc LIKE '%' || ? || '%' AND length(?) >= 5) ORDER BY CASE WHEN name_lc = ? THEN 0 ELSE 1 END, length(name_lc) DESC LIMIT 20");
    this.adjacentNodes = this.database.prepare("SELECT e.relation, n.id, n.kind, n.name FROM edges e JOIN nodes n ON n.id = CASE WHEN e.from_id = ? THEN e.to_id ELSE e.from_id END WHERE e.from_id = ? OR e.to_id = ? LIMIT 100");
    this.linkedDocuments = this.database.prepare("SELECT n.name AS documentId, e.relation FROM edges e JOIN nodes n ON n.id = CASE WHEN e.from_id = ? THEN e.to_id ELSE e.from_id END WHERE (e.from_id = ? OR e.to_id = ?) AND n.kind = 'document' LIMIT 100");
  }

  async upsert(documents: DocumentChunk[]): Promise<void> {
    const transaction = this.database.transaction((rows: DocumentChunk[]) => {
      for (const document of rows) {
        const pointId = documentId(document);
        const doc = entity("document", pointId);
        this.deleteDocumentEdges.run(doc.id);
        for (const relation of createRelations(document, pointId)) {
          this.insertNode.run(relation.from.id, relation.from.kind, relation.from.name, normalized(relation.from.name));
          this.insertNode.run(relation.to.id, relation.to.kind, relation.to.name, normalized(relation.to.name));
          this.insertEdge.run(relation.from.id, relation.relation, relation.to.id);
        }
      }
    });
    transaction(documents);
  }

  async search(query: string, limit: number): Promise<GraphMatch[]> {
    const terms = [...new Set(tokenize(query))].slice(0, 12);
    const matches = new Map<string, GraphMatch>();
    const nodeRows = new Map<string, Entity>();
    for (const term of terms) {
      const rows = this.searchNodes.all(term, term, term, term) as Array<{ id: string; kind: string; name: string }>;
      for (const row of rows) nodeRows.set(row.id, row);
    }
    for (const matched of nodeRows.values()) {
      const adjacent = this.adjacentNodes.all(matched.id, matched.id, matched.id) as Array<{ relation: string; id: string; kind: string; name: string }>;
      for (const neighbor of adjacent) {
        const directDocuments = neighbor.kind === "document"
          ? [{ documentId: neighbor.name, relation: neighbor.relation }]
          : this.linkedDocuments.all(neighbor.id, neighbor.id, neighbor.id) as Array<{ documentId: string; relation: string }>;
        const score = terms.includes(normalized(matched.name)) ? 1 : 0.75;
        for (const linked of directDocuments) {
          const relationPath = `${matched.name} —${neighbor.relation}→ ${neighbor.kind === "document" ? "document" : `${neighbor.name} —${linked.relation}→ document`}`;
          const current = matches.get(linked.documentId);
          if (!current || score > current.score || (score === current.score && relationPath.length > current.relationPath.length)) {
            matches.set(linked.documentId, { documentId: linked.documentId, matchedEntity: matched.name, relationPath, score });
          }
        }
      }
    }
    return [...matches.values()].sort((a, b) => b.score - a.score).slice(0, limit);
  }

  close(): void {
    this.database.close();
  }
}
