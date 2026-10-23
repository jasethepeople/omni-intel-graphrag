import { createHash } from "node:crypto";
import type { DocumentChunk } from "../types.ts";

export type NormalizedAdvisory = {
  id: string;
  aliases: string[];
  title: string;
  description: string;
  severity?: number;
  severityLabel?: string;
  published?: string;
  modified?: string;
  references: string[];
  affected: Array<{ ecosystem?: string; package?: string; versions: string[] }>;
  source: string;
  raw: Record<string, unknown>;
};

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function extractNvdSeverity(metrics: any): { score?: number; label?: string } {
  const rows = [metrics?.cvssMetricV40, metrics?.cvssMetricV31, metrics?.cvssMetricV30, metrics?.cvssMetricV2];
  for (const row of rows) {
    const metric = Array.isArray(row) ? row[0]?.cvssData : undefined;
    if (metric && typeof metric.baseScore === "number") {
      return { score: metric.baseScore, label: stringValue(metric.baseSeverity) };
    }
  }
  return {};
}

function extractOsvSeverity(raw: any): { score?: number; label?: string } {
  const numeric = Number(raw?.database_specific?.severityScore ?? raw?.database_specific?.cvssScore);
  const label = stringValue(raw?.database_specific?.severity);
  return {
    score: Number.isFinite(numeric) && numeric >= 0 && numeric <= 10 ? numeric : undefined,
    label: label?.toUpperCase(),
  };
}

function extractNvdAffected(configurations: unknown): NormalizedAdvisory["affected"] {
  if (!Array.isArray(configurations)) return [];
  const matches: Array<{ criteria?: string; versionStartIncluding?: string; versionStartExcluding?: string; versionEndIncluding?: string; versionEndExcluding?: string }> = [];
  const visit = (nodes: unknown): void => {
    if (!Array.isArray(nodes)) return;
    for (const node of nodes as any[]) {
      if (Array.isArray(node.cpeMatch)) matches.push(...node.cpeMatch);
      visit(node.children);
    }
  };
  for (const configuration of configurations as any[]) visit(configuration.nodes);
  return matches.flatMap((match) => {
    if (typeof match.criteria !== "string") return [];
    const cpe = match.criteria.split(":");
    const packageName = cpe.length > 4 ? cpe[4] : undefined;
    const versions = [match.versionStartIncluding, match.versionStartExcluding, match.versionEndIncluding, match.versionEndExcluding]
      .filter((value): value is string => typeof value === "string" && value !== "*");
    const cpeVersion = cpe[5];
    if (cpeVersion && cpeVersion !== "*" && cpeVersion !== "-") versions.push(cpeVersion);
    return [{ ecosystem: cpe[2] === "a" ? "application" : cpe[2], package: packageName, versions: [...new Set(versions)] }];
  });
}

export function normalizeAdvisory(rawInput: unknown): NormalizedAdvisory {
  if (!rawInput || typeof rawInput !== "object") throw new Error("Vulnerability advisory must be a JSON object");
  const raw = rawInput as any;
  const nvd = raw.cve ? raw.cve : raw;
  const cveId = stringValue(nvd.id) ?? stringValue(raw.id) ?? stringValue(raw.cveId);
  if (!cveId) throw new Error("Vulnerability advisory id is required");
  const nvdDescription = nvd.descriptions?.find((row: any) => row.lang === "en")?.value;
  const description = stringValue(nvdDescription) ?? stringValue(raw.details) ?? stringValue(raw.description) ?? "No description supplied.";
  const nvdMetric = extractNvdSeverity(nvd.metrics ?? raw.metrics);
  const osvMetric = extractOsvSeverity(raw);
  const rawSeverity = typeof raw.severityScore === "number" || (typeof raw.severityScore === "string" && raw.severityScore.trim())
    ? Number(raw.severityScore)
    : Number.NaN;
  const severity = nvdMetric.score ?? osvMetric.score ?? (Number.isFinite(rawSeverity) ? rawSeverity : undefined);
  const references = [
    ...(Array.isArray(raw.references) ? raw.references.map((item: any) => typeof item === "string" ? item : item?.url) : []),
    ...(Array.isArray(nvd.references) ? nvd.references.map((item: any) => item?.url) : []),
  ].filter((value: unknown): value is string => typeof value === "string" && /^https:\/\//.test(value));
  const affected = Array.isArray(raw.affected)
    ? raw.affected.map((item: any) => ({
      ecosystem: stringValue(item.package?.ecosystem),
      package: stringValue(item.package?.name),
      versions: [
        ...(Array.isArray(item.versions) ? item.versions.map(String) : []),
        ...(Array.isArray(item.ranges) ? item.ranges.flatMap((range: any) => (range.events ?? []).map((event: any) => event.introduced ?? event.fixed ?? event.last_affected).filter(Boolean).map(String)) : []),
      ],
    }))
    : extractNvdAffected(nvd.configurations);
  const aliases = [...new Set([...(Array.isArray(raw.aliases) ? raw.aliases.map(String) : []), cveId])];
  const source = raw.database_specific?.url || raw.source || (raw.cve || nvd.metrics || nvd.configurations || nvd.lastModified ? "NVD" : "OSV");
  return {
    id: cveId,
    aliases,
    title: stringValue(raw.summary) ?? `${cveId} security advisory`,
    description,
    severity: typeof severity === "number" && Number.isFinite(severity) && severity >= 0 && severity <= 10 ? severity : undefined,
    severityLabel: nvdMetric.label ?? osvMetric.label,
    published: stringValue(raw.published) ?? stringValue(nvd.published),
    modified: stringValue(raw.modified) ?? stringValue(nvd.lastModified),
    references: [...new Set(references)],
    affected,
    source: String(source),
    raw: rawInput as Record<string, unknown>,
  };
}

export function advisoryToDocument(advisoryInput: unknown): DocumentChunk {
  const advisory = normalizeAdvisory(advisoryInput);
  const packageNames = advisory.affected.map((item) => [item.ecosystem, item.package].filter(Boolean).join("/")).filter(Boolean);
  const content = [
    `Advisory: ${advisory.id}`,
    `Aliases: ${advisory.aliases.join(", ")}`,
    `Severity: ${advisory.severityLabel ?? "unknown"}${advisory.severity === undefined ? "" : ` (${advisory.severity}/10)`}`,
    `Affected packages: ${packageNames.join(", ") || "not specified"}`,
    `Affected versions: ${advisory.affected.flatMap((item) => item.versions).join(", ") || "not specified"}`,
    `Description: ${advisory.description}`,
    `References: ${advisory.references.join(" | ") || "none"}`,
  ].join("\n");
  const id = createHash("sha256").update(`${advisory.id}:${advisory.modified ?? advisory.published ?? ""}`).digest("hex").slice(0, 20);
  return {
    id,
    title: advisory.title,
    content,
    source: advisory.references[0] ?? `${advisory.source}:${advisory.id}`,
    modality: "vulnerability",
    fileType: "security-advisory",
    tags: ["security", "vulnerability", advisory.id, ...(advisory.severityLabel ? [advisory.severityLabel.toLowerCase()] : []), ...packageNames],
    severity: advisory.severity,
    createdAt: advisory.modified ?? advisory.published ?? new Date().toISOString(),
    metadata: {
      advisoryId: advisory.id,
      aliases: advisory.aliases,
      severityLabel: advisory.severityLabel,
      published: advisory.published,
      modified: advisory.modified,
      references: advisory.references,
      affected: advisory.affected,
      source: advisory.source,
    },
  };
}

export async function fetchOsvAdvisory(id: string): Promise<unknown> {
  const safeId = encodeURIComponent(id.trim());
  const response = await fetch(`https://api.osv.dev/v1/vulns/${safeId}`, {
    signal: AbortSignal.timeout(15_000),
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new Error(`OSV lookup failed (${response.status})`);
  return response.json();
}

export async function fetchNvdAdvisoryPage(input: { start: string; end: string; startIndex?: number; pageSize?: number }): Promise<{ advisories: unknown[]; totalResults: number; startIndex: number; resultsPerPage: number }> {
  const start = new Date(input.start);
  const end = new Date(input.end);
  const startIndex = input.startIndex ?? 0;
  const pageSize = input.pageSize ?? 250;
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end) {
    throw new Error("NVD sync requires a valid start and end date, with start before end");
  }
  if (!Number.isInteger(startIndex) || startIndex < 0) throw new Error("NVD startIndex must be a non-negative integer");
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 500) throw new Error("NVD pageSize must be an integer from 1 to 500");
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("lastModStartDate", start.toISOString());
  url.searchParams.set("lastModEndDate", end.toISOString());
  url.searchParams.set("startIndex", String(startIndex));
  url.searchParams.set("resultsPerPage", String(pageSize));
  const response = await fetch(url, {
    signal: AbortSignal.timeout(30_000),
    headers: {
      accept: "application/json",
      ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}),
    },
  });
  if (!response.ok) throw new Error(`NVD synchronization failed (${response.status})`);
  const result = await response.json() as {
    totalResults?: number;
    startIndex?: number;
    resultsPerPage?: number;
    vulnerabilities?: Array<{ cve: unknown }>;
  };
  return {
    advisories: (result.vulnerabilities ?? []).map((item) => item.cve),
    totalResults: Number(result.totalResults ?? 0),
    startIndex: Number(result.startIndex ?? startIndex),
    resultsPerPage: Number(result.resultsPerPage ?? pageSize),
  };
}

export async function fetchOsvPackageAdvisories(ecosystem: string, packageName: string): Promise<unknown[]> {
  const response = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    signal: AbortSignal.timeout(30_000),
    body: JSON.stringify({ package: { ecosystem: ecosystem.trim(), name: packageName.trim() } }),
  });
  if (!response.ok) throw new Error(`OSV package lookup failed (${response.status})`);
  const result = await response.json() as { vulns?: unknown[] };
  return result.vulns ?? [];
}


export async function fetchNvdAdvisory(id: string): Promise<unknown> {
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", id.trim());
  const response = await fetch(url, {
    signal: AbortSignal.timeout(20_000),
    headers: {
      accept: "application/json",
      ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}),
    },
  });
  if (!response.ok) throw new Error(`NVD lookup failed (${response.status})`);
  const result = await response.json() as { vulnerabilities?: Array<{ cve: unknown }> };
  const advisory = result.vulnerabilities?.[0]?.cve;
  if (!advisory) throw new Error(`NVD returned no advisory for ${id}`);
  return advisory;
}
