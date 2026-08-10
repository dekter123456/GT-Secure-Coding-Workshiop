#!/usr/bin/env node
/**
 * Zero-dependency static file server for the Secure Coding Workshop.
 *
 * Usage:
 *   node server.js            # serves on http://localhost:8000
 *   PORT=3000 node server.js  # custom port
 *
 * ไม่ต้องติดตั้ง dependency ใด ๆ ใช้ได้เลยด้วย Node 14+.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8000;
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.map': 'application/json; charset=utf-8',
};

const server = http.createServer((req, res) => {
  try {
    let urlPath = decodeURIComponent(req.url.split('?')[0]);
    if (urlPath === '/') urlPath = '/index.html';

    // Resolve safely inside ROOT to prevent path traversal.
    const filePath = path.normalize(path.join(ROOT, urlPath));
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403);
      return res.end('Forbidden');
    }

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('404 Not Found: ' + urlPath);
      }
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    });
  } catch (e) {
    res.writeHead(500);
    res.end('Server error');
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('  Secure Coding Workshop กำลังรันอยู่ที่:');
  console.log('  \x1b[32mhttp://localhost:' + PORT + '\x1b[0m');
  console.log('');
  console.log('  กด Ctrl+C เพื่อหยุด');
  console.log('');
});
