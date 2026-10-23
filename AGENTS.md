# Project guidance

- This directory is the source of truth for the Omni-Intel GraphRAG Gateway.
- Runtime: Bun + strict TypeScript. Keep the service self-hosted and local-first; do not introduce hosted model dependencies.
- Read `README.md` and `.env.example` before changing architecture or deployment assumptions.
- `src/ingestors/` normalizes inputs into `DocumentChunk`; `src/vector/` owns embedding and storage; `src/core/` owns HTTP, orchestration, and citation validation.
- Keep filesystem repository ingestion CLI-only. HTTP ingestion accepts caller-supplied file contents and must not read arbitrary server paths.
- Keep tests deterministic and offline by using the in-memory vector backend. Live Qdrant tests are opt-in.
- Run `bun test` and `bun run typecheck` after implementation changes.
