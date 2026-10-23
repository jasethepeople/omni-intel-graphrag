export type Modality = "code" | "vulnerability" | "media" | "text";

export type DocumentChunk = {
  id: string;
  title: string;
  content: string;
  source: string;
  modality: Modality;
  fileType: string;
  tags: string[];
  severity?: number;
  createdAt: string;
  metadata: Record<string, unknown>;
};

export type SearchHit = {
  id: string;
  score: number;
  document: DocumentChunk;
};

export type QueryRequest = {
  query: string;
  limit?: number;
};

export type IngestResult = {
  indexed: number;
  ids: string[];
};
