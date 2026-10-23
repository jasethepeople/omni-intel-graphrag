import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join } from "node:path";
import { createHash } from "node:crypto";
import type { DocumentChunk } from "../types.ts";
import { splitText } from "./text.ts";

export type MediaInput = {
  filename: string;
  mimeType: string;
  bytes: Uint8Array;
};

const audioTypes = new Set(["audio/mpeg", "audio/mp3", "audio/wav", "audio/x-wav", "audio/flac", "audio/ogg", "audio/mp4", "audio/aac", "audio/webm"]);
const videoTypes = new Set(["video/mp4", "video/webm", "video/quicktime", "video/x-matroska", "video/mpeg"]);
const imageTypes = new Set(["image/png", "image/jpeg", "image/webp", "image/tiff", "image/bmp"]);

function run(command: string, args: string[], timeoutMs = 300_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === null) reject(new Error(`${command} timed out after ${timeoutMs}ms`));
      else resolve({ code, stdout, stderr });
    });
  });
}

function safeFilename(filename: string): string {
  const clean = basename(filename).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
  return clean || `upload${extname(filename) || ".bin"}`;
}

function mediaChunks(input: MediaInput, text: string, modality: "audio" | "video" | "image"): DocumentChunk[] {
  const normalized = text.trim();
  if (!normalized) throw new Error(`No text could be extracted from ${input.filename}`);
  const pieces = splitText(normalized);
  return pieces.map((piece, index) => {
    const id = createHash("sha256").update(`${input.filename}:${index}:${piece}`).digest("hex").slice(0, 20);
    return {
      id,
      title: `${input.filename}${pieces.length > 1 ? ` — part ${index + 1}` : ""}`,
      content: [
        `Media file: ${input.filename}`,
        `Media type: ${input.mimeType}`,
        `Extracted ${modality} content:`,
        piece.trim(),
      ].join("\n"),
      source: input.filename,
      modality: "media",
      fileType: input.mimeType,
      tags: ["media", modality, "transcript"],
      createdAt: new Date().toISOString(),
      metadata: { mediaType: modality, mimeType: input.mimeType, part: index + 1, parts: pieces.length },
    };
  });
}

async function describeImageLocally(input: MediaInput): Promise<string> {
  const model = process.env.OLLAMA_VISION_MODEL;
  if (!model) return "";
  const baseUrl = (process.env.OLLAMA_URL || "http://127.0.0.1:11434").replace(/\/$/, "");
  const response = await fetch(`${baseUrl}/api/generate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(Number(process.env.VISION_TIMEOUT_MS || 120_000)),
    body: JSON.stringify({
      model,
      prompt: "Describe the visible scene, objects, actions, and any readable text accurately. Return concise factual Markdown. Do not infer details that are not visible.",
      images: [Buffer.from(input.bytes).toString("base64")],
      stream: false,
    }),
  });
  if (!response.ok) throw new Error(`Local image description failed (${response.status})`);
  const result = await response.json() as { response?: string };
  return result.response?.trim() ?? "";
}

export async function processMedia(input: MediaInput): Promise<DocumentChunk[]> {
  const mime = input.mimeType.toLowerCase().split(";")[0]!.trim();
  const mode = audioTypes.has(mime) ? "audio" : videoTypes.has(mime) ? "video" : imageTypes.has(mime) ? "image" : undefined;
  if (!mode) throw new Error(`Unsupported media type: ${input.mimeType}`);

  const tempDir = await mkdtemp(join(tmpdir(), "omni-intel-media-"));
  const sourcePath = join(tempDir, safeFilename(input.filename));
  try {
    await writeFile(sourcePath, input.bytes);
    if (mode === "image") {
      const visualDescription = await describeImageLocally(input);
      const result = await run(process.env.TESSERACT_BIN || "tesseract", [sourcePath, "stdout"], 60_000);
      if (result.code !== 0) throw new Error(`Image OCR failed: ${result.stderr.trim() || `exit ${result.code}`}`);
      const extractedText = result.stdout.trim();
      const content = [
        visualDescription ? `Visual description:\n${visualDescription}` : "",
        extractedText ? `OCR text:\n${extractedText}` : "",
        !visualDescription && !extractedText ? "No readable text was detected. Set OLLAMA_VISION_MODEL to enable a local visual description." : "",
      ].filter(Boolean).join("\n\n");
      return mediaChunks(input, content, "image");
    }

    let audioPath = sourcePath;
    if (mode === "video") {
      audioPath = join(tempDir, "audio.wav");
      const result = await run(process.env.FFMPEG_BIN || "ffmpeg", ["-nostdin", "-v", "error", "-i", sourcePath, "-vn", "-ac", "1", "-ar", "16000", "-y", audioPath]);
      if (result.code !== 0) throw new Error(`Video audio extraction failed: ${result.stderr.trim()}`);
    }
    const outputDir = join(tempDir, "transcript");
    const result = await run(process.env.WHISPER_BIN || "whisper", [
      audioPath,
      "--model", process.env.WHISPER_MODEL || "base",
      "--output_format", "txt",
      "--output_dir", outputDir,
      "--fp16", "False",
    ]);
    if (result.code !== 0) throw new Error(`Whisper transcription failed: ${result.stderr.trim() || `exit ${result.code}`}`);
    const transcriptFile = join(outputDir, `${basename(audioPath, extname(audioPath))}.txt`);
    const transcript = await readFile(transcriptFile, "utf8");
    return mediaChunks(input, transcript, mode);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
