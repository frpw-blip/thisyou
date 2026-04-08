const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Load sites data
const SITES = JSON.parse(fs.readFileSync(path.join(__dirname, 'wmn-data.json'), 'utf8'));

app.use(express.static(path.join(__dirname, 'public')));

// Helper: fetch URL with timeout
function fetchUrl(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/json,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      timeout: timeoutMs,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size < 200000) body += chunk;
      });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, body, headers: res.headers });
      });
    });
    req.on('error', (e) => reject(e));
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// Follow redirects (up to 3)
async function fetchWithRedirects(url, maxRedirects = 3) {
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const res = await fetchUrl(current);
    if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
      let loc = res.headers.location;
      if (loc.startsWith('/')) {
        const u = new URL(current);
        loc = u.origin + loc;
      }
      return { ...res, finalUrl: current, redirected: true, redirectStatusCode: res.statusCode };
    }
    return { ...res, finalUrl: current, redirected: false };
  }
}

// Check a single site for a username
async function checkSite(site, username) {
  const url = site.uri_check.replace('{account}', encodeURIComponent(username));
  const result = { name: site.name, url, cat: site.cat, status: 'not-found', error: null };

  try {
    const res = await fetchWithRedirects(url);
    const code = res.statusCode;
    const body = res.body || '';

    // Check for "missing" signals first
    if (site.m_code && code === site.m_code) {
      result.status = 'not-found';
      return result;
    }
    if (res.redirected && site.m_code && res.redirectStatusCode === site.m_code) {
      result.status = 'not-found';
      return result;
    }
    if (site.m_string && body.includes(site.m_string)) {
      result.status = 'not-found';
      return result;
    }

    // Check for "exists" signals
    const codeMatch = (code === site.e_code);
    const stringMatch = site.e_string ? body.includes(site.e_string) : true;

    if (codeMatch && stringMatch) {
      result.status = 'found';
    } else {
      result.status = 'not-found';
    }
  } catch (e) {
    result.status = 'error';
    result.error = e.message;
  }
  return result;
}

// SSE scan endpoint
app.get('/api/scan/:username', (req, res) => {
  const username = req.params.username;
  if (!username || username.length < 2 || username.length > 64) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  const catFilter = req.query.cat || 'all';

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  let filtered = catFilter === 'all' ? SITES : SITES.filter(s => s.cat === catFilter);
  const total = filtered.length;
  let completed = 0;
  let found = 0;
  let closed = false;

  res.on('close', () => { closed = true; });

  // Send init
  res.write(`data: ${JSON.stringify({ type: 'init', total, username })}\n\n`);

  // Process in batches of 15 concurrent
  const CONCURRENCY = 15;
  let queue = [...filtered];

  async function processBatch() {
    while (queue.length > 0 && !closed) {
      const batch = queue.splice(0, CONCURRENCY);
      const promises = batch.map(site => checkSite(site, username));
      const results = await Promise.allSettled(promises);

      for (const r of results) {
        if (closed) return;
        completed++;
        const val = r.status === 'fulfilled' ? r.value : { name: '?', status: 'error', error: r.reason?.message };
        if (val.status === 'found') found++;

        res.write(`data: ${JSON.stringify({
          type: 'result',
          ...val,
          progress: completed,
          total,
          found,
        })}\n\n`);
      }
    }

    if (!closed) {
      res.write(`data: ${JSON.stringify({ type: 'done', total: completed, found })}\n\n`);
      res.end();
    }
  }

  processBatch().catch(e => {
    if (!closed) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: e.message })}\n\n`);
      res.end();
    }
  });
});

// Stats endpoint
app.get('/api/stats', (req, res) => {
  const cats = [...new Set(SITES.map(s => s.cat))].sort();
  res.json({ totalSites: SITES.length, categories: cats });
});

app.listen(PORT, () => {
  console.log(`WhatsMyName OSINT Matrix:Reloaded — port ${PORT} — ${SITES.length} sites`);
});
