// Minimal static server for the evil-napps repo — like `python3 -m http.server`
// but with per-request header control, which the rungs need:
//   /harness/?lcsp=strict  →  Content-Security-Policy: script-src 'self'
//                             (a CSP-hardened launcher: no inline handlers —
//                              the last line of defense when a launcher renders
//                              napp metadata as HTML. The harness's own script
//                              is external (harness/index.js) so 'self' holds
//                              injected handlers without breaking the launcher.)
// Run: node tests/_server.mjs [port]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const PORT = Number(process.argv[2] || process.env.EVIL_PORT || 8899);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    let path = decodeURIComponent(url.pathname);
    if (path.endsWith('/')) path += 'index.html';
    const file = normalize(join(root, path));
    if (!file.startsWith(root)) {
      res.writeHead(403).end('forbidden');
      return;
    }
    let body;
    try {
      body = await readFile(file);
    } catch (_) {
      if (path === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('evil-napps static server — the harness lives at /harness/\n');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found: ' + path);
      return;
    }
    const headers = { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' };
    if (path === '/harness/index.html' && url.searchParams.get('lcsp') === 'strict') {
      headers['Content-Security-Policy'] = "script-src 'self'";
    }
    res.writeHead(200, headers);
    res.end(body);
  } catch (err) {
    try { res.writeHead(500); res.end('server error'); } catch (_) {}
  }
});

server.listen(PORT, () => {
  console.log(`evil-napps static server on http://localhost:${PORT} (repo: ${root})`);
});
