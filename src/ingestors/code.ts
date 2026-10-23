import { createHash } from "node:crypto";
import { readdir, readFile, realpath } from "node:fs/promises";
import { extname, join, relative, resolve, sep } from "node:path";
import ts from "typescript";
import type { DocumentChunk } from "../types.ts";

export type CodeInputFile = { path: string; content: string };

const supportedExtensions = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
const ignoredDirectories = new Set([".git", "node_modules", "dist", "build", "coverage", ".next", ".nuxt", ".cache"]);
const chunkLimit = 12_000;

function stableChunkId(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 20);
}

function safeVirtualPath(input: string): string {
  if (!input || input.includes("\0")) throw new Error("Code file path must be a non-empty virtual path");
  const normalized = input.replaceAll("\\", "/");
  if (normalized.split("/").includes("..")) throw new Error(`Path traversal is not allowed: ${input}`);
  return normalized.replace(/^\.\//, "");
}

function fileExports(node: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current && !ts.isSourceFile(current)) {
    const modifiers = ts.canHaveModifiers(current) ? ts.getModifiers(current) : undefined;
    if (modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword || modifier.kind === ts.SyntaxKind.DefaultKeyword)) return true;
    current = current.parent;
  }
  return false;
}

function functionName(node: ts.Node, fallback: string): string {
  if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isMethodSignature(node)) && node.name) {
    return node.name.getText();
  }
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) return node.name.text;
  return fallback;
}

function addFunctionChunks(
  node: ts.Node,
  sourceFile: ts.SourceFile,
  filePath: string,
  imports: string[],
  output: DocumentChunk[],
  sourceLabel: string,
  className?: string,
): void {
  const isFunction = ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) ||
    (ts.isVariableDeclaration(node) && !!node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)));

  if (isFunction) {
    const name = functionName(node, "anonymous");
    const qualifiedName = className ? `${className}.${name}` : name;
    const signatureNode = ts.isVariableDeclaration(node) ? node.initializer! : node;
    const body = "body" in signatureNode ? (signatureNode as ts.FunctionLikeDeclaration).body : undefined;
    const signatureEnd = body?.getStart(sourceFile) ?? signatureNode.getEnd();
    const signature = signatureNode.getSourceFile().text.slice(signatureNode.getStart(sourceFile), signatureEnd).trim();
    const source = node.getText(sourceFile).slice(0, chunkLimit);
    const exported = fileExports(node) || fileExports(node.parent);
    output.push({
      id: stableChunkId(`${filePath}:${qualifiedName}:${source}`),
      title: `${qualifiedName} — ${filePath}`,
      content: [
        `Symbol: ${qualifiedName}`,
        `Signature: ${signature}`,
        `Exports: ${exported ? "yes" : "no"}`,
        `Dependencies: ${imports.join(", ") || "none"}`,
        "Source:",
        source,
      ].join("\n"),
      source: sourceLabel,
      modality: "code",
      fileType: extname(filePath).slice(1) || "source",
      tags: ["code", "function", ...(exported ? ["exported"] : [])],
      createdAt: new Date().toISOString(),
      metadata: { symbol: qualifiedName, signature, exported, dependencies: imports },
    });
  }

  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    const name = node.name?.text ?? "anonymous-class";
    for (const member of node.members) addFunctionChunks(member, sourceFile, filePath, imports, output, sourceLabel, name);
    return;
  }

  if (!isFunction) {
    ts.forEachChild(node, (child) => addFunctionChunks(child, sourceFile, filePath, imports, output, sourceLabel, className));
  }
}

export function parseCodeFile(input: CodeInputFile, source = input.path): DocumentChunk[] {
  const path = safeVirtualPath(input.path);
  const extension = extname(path).toLowerCase();
  if (!supportedExtensions.has(extension)) {
    return [{
      id: stableChunkId(`${path}:${input.content}`),
      title: path,
      content: input.content.slice(0, chunkLimit),
      source,
      modality: "code",
      fileType: extension.slice(1) || "text",
      tags: ["code", "file"],
      createdAt: new Date().toISOString(),
      metadata: { path, parseMode: "plain-text" },
    }];
  }

  const scriptKind = extension === ".tsx" ? ts.ScriptKind.TSX :
    extension === ".jsx" ? ts.ScriptKind.JSX :
      [".js", ".mjs", ".cjs"].includes(extension) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(path, input.content, ts.ScriptTarget.Latest, true, scriptKind);
  const imports: string[] = [];
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) imports.push(statement.moduleSpecifier.text);
    if (ts.isExportDeclaration(statement) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) imports.push(statement.moduleSpecifier.text);
  }
  const chunks: DocumentChunk[] = [];
  addFunctionChunks(sourceFile, sourceFile, path, [...new Set(imports)], chunks, source);
  if (chunks.length === 0 || imports.length > 0) {
    const digest = createHash("sha256").update(input.content).digest("hex").slice(0, 20);
    chunks.push({
      id: stableChunkId(`${path}:module:${digest}`),
      title: `Module ${path}`,
      content: [
        `File: ${path}`,
        `Imports: ${imports.join(", ") || "none"}`,
        "Module source:",
        input.content.slice(0, chunkLimit),
      ].join("\n"),
      source,
      modality: "code",
      fileType: extension.slice(1),
      tags: ["code", "module"],
      createdAt: new Date().toISOString(),
      metadata: { path, imports: [...new Set(imports)], parseDiagnostics: (sourceFile as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics.length },
    });
  }
  return chunks;
}

export async function parseRepository(rootDirectory: string): Promise<DocumentChunk[]> {
  const root = await realpath(resolve(rootDirectory));
  const files: CodeInputFile[] = [];
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(absolutePath);
        continue;
      }
      if (!entry.isFile() || !supportedExtensions.has(extname(entry.name).toLowerCase())) continue;
      const content = await readFile(absolutePath, "utf8");
      const virtualPath = relative(root, absolutePath).split(sep).join("/");
      files.push({ path: virtualPath, content });
    }
  };
  await visit(root);
  return files.flatMap((file) => parseCodeFile(file, `${root}/${file.path}`));
}
