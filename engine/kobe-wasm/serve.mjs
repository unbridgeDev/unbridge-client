// Minimal static server for the wasm demo (correct wasm MIME so the browser
// instantiates it). Dev-only.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
const ROOT = new URL(".", import.meta.url).pathname;
const MIME = { ".html":"text/html", ".js":"text/javascript", ".mjs":"text/javascript",
  ".wasm":"application/wasm", ".json":"application/json", ".css":"text/css", ".ts":"text/plain" };
const port = process.env.PORT ? Number(process.env.PORT) : 4600;
createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p === "/") p = "/demo.html";
    const file = normalize(join(ROOT, p));
    if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }
    const body = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch { res.writeHead(404).end("not found"); }
}).listen(port, () => console.log(`serving kobe-wasm demo on http://localhost:${port}`));
