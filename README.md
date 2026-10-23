# Omni-Intel GraphRAG Gateway

A self-hosted Bun/TypeScript gateway that ingests source code, security advisories, text, and local media into hybrid Qdrant vectors plus a persistent SQLite entity graph. Query retrieval runs local, citation-checks every returned context item, and formats evidence for a downstream LLM; answer generation is intentionally not tied to a hosted model.

## Run locally

Requirements: Bun 1.3+, Docker Compose for Qdrant, and optional `ffmpeg`, `whisper`, and `tesseract` binaries for media extraction.

```sh
bun install
cp .env.example .env
docker compose up -d qdrant
bun run dev
```

The API binds to `127.0.0.1:8080` by default. Set `API_KEY` before binding to a non-loopback address. `.env` is ignored by Git. Qdrant data persists in the Compose volume; the entity graph defaults to `./data/knowledge-graph.sqlite`.

## Embeddings and local media

The default `EMBEDDING_PROVIDER=hash` is deterministic and requires no model service. It produces feature-hashed dense vectors and sparse keyword vectors; it is useful for local development and lexical retrieval, but is not a substitute for a trained semantic embedding model. For stronger semantic retrieval, run Ollama locally, set `EMBEDDING_PROVIDER=ollama`, choose `OLLAMA_EMBED_MODEL`, and set `VECTOR_DIMENSION` to that model's output dimension (for example, `nomic-embed-text` commonly uses 768). The named Qdrant collection must match that dimension.

Audio/video transcription uses the configured local Whisper CLI; video audio is extracted with FFmpeg. Images use local Tesseract OCR, with an optional local Ollama vision model set as `OLLAMA_VISION_MODEL`. No media is sent to a hosted model. Install the relevant tools and model weights on the machine running the service.

## API

All request/response bodies are JSON except multipart media uploads. Set `Authorization: Bearer $API_KEY` when an API key is configured.

- `GET /health` — process health check.
- `POST /api/v1/ingest/code` — `{ "source": "repo", "files": [{ "path": "src/app.ts", "content": "..." }] }` or one `{ "path", "content" }` file. TypeScript's parser extracts function/method symbols, signatures, imports, exports, and file-level chunks. The HTTP endpoint only accepts supplied file contents; it never reads arbitrary server paths.
- `POST /api/v1/ingest/vulnerability` — ingest a raw advisory as the body, `{ "advisory": {...} }`, or `{ "advisories": [...] }`. Set `{ "fetch": true, "provider": "osv"|"nvd", "id": "..." }` for a live advisory lookup; use `{ "provider": "osv", "ecosystem": "npm", "packageName": "..." }` for an OSV package query. NVD modification-feed requests use `{ "provider": "nvd", "start": "ISO-8601", "end": "ISO-8601", "startIndex": 0, "pageSize": 250 }`; date windows are limited to 120 days, and responses include `feed.nextStartIndex` for pagination. NVD API key is optional and read from `NVD_API_KEY`.
- `POST /api/v1/ingest/text` — `{ "title": "...", "source": "...", "content": "...", "tags": ["..."] }`.
- `POST /api/v1/ingest/media` — multipart field `file`, or JSON `{ "filename": "meeting.wav", "mimeType": "audio/wav", "base64": "..." }`.
- `POST /api/v1/query` — `{ "query": "...", "limit": 8 }`. Returns a retrieval plan, checked citations, and evidence context. Query decomposition, parallel hybrid retrieval, and SQLite graph traversal require no hosted LLM.

Example:

```sh
curl -s http://127.0.0.1:8080/api/v1/ingest/code \
  -H 'content-type: application/json' \
  -d '{"files":[{"path":"src/example.ts","content":"export const answer = 42;"}]}'
```

Regular JSON requests default to 5 MB; media-upload request bodies have a separate 50 MiB cap. For JSON/base64 media, the cap applies to the encoded JSON body. Override with `MAX_JSON_BYTES` and `MAX_MEDIA_BYTES`.

## Repository CLI

The CLI scans supported JavaScript/TypeScript files while skipping dependency/build folders and symbolic links, then writes to Qdrant and the SQLite graph:

```sh
bun run ingest:repo -- /absolute/path/to/repository
```

## Tests

The normal suite is deterministic and offline:

```sh
bun test
bun run typecheck
```

It covers AST extraction, direct advisory ingestion, citation-grounded hybrid retrieval, SQLite graph traversal, request limits, and media-adapter routing. To exercise a running local Qdrant instance, set `QDRANT_INTEGRATION=1` and run `bun test`; this writes a small integration point to the configured collection.

## Layout

- `src/ingestors/` — AST code parsing, OSV/NVD normalization and sync, local media processing, and text chunking.
- `src/vector/` — Qdrant dense/sparse collection and retrieval, deterministic memory backend, and SQLite entity graph.
- `src/core/` — Bun HTTP routes, security checks, and graph-enriched retrieval orchestration.
- `tests/gateway.test.ts` — offline API tests plus optional live-Qdrant integration.
