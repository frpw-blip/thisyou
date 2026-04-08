const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({limit:'10mb'}));
app.use(express.static(path.join(__dirname, 'public')));

const SITES = JSON.parse(fs.readFileSync(path.join(__dirname, 'wmn-data.json'), 'utf8'));

// ═══ FACE SEARCH PROXY ═══
app.post('/api/face-search', async (req, res) => {
  const { image, source, results: maxResults } = req.body;
  if (!image) return res.status(400).json({ error: 'No image' });

  try {
    // Step 1: detectFaces
    const detectRes = await jsonRpc('detectFaces', { image });
    if (!detectRes.result || !detectRes.result.faces || detectRes.result.faces.length === 0) {
      return res.json({ success: false, error: 'no_faces', message: 'Aucun visage détecté par Search4faces' });
    }

    const imgId = detectRes.result.image;
    const face = detectRes.result.faces[0];

    // Step 2: searchFace
    const searchRes = await jsonRpc('searchFace', {
      image: imgId,
      face,
      source: source || 'vkok_avatar',
      hidden: true,
      results: maxResults || '50',
      lang: 'en'
    });

    if (searchRes.result && searchRes.result.profiles) {
      return res.json({ success: true, profiles: searchRes.result.profiles });
    } else if (searchRes.error) {
      return res.json({ success: false, error: 'api_error', message: searchRes.error.message || 'API error' });
    }
    return res.json({ success: false, error: 'no_results', message: 'Aucun résultat trouvé' });
  } catch (e) {
    return res.json({ success: false, error: 'proxy_error', message: e.message });
  }
});

function jsonRpc(method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', method, id: 'thisyou-' + Date.now(), params });
    const options = {
      hostname: 'search4faces.com',
      port: 443,
      path: '/api/json-rpc/v1',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': 'https://search4faces.com',
        'Referer': 'https://search4faces.com/en/vkok/index.html',
      },
      timeout: 30000,
    };
    const req = https.request(options, r => {
      let data = '';
      r.on('data', c => data += c);
      r.on('end', () => { try { resolve(JSON.parse(data)) } catch(e) { reject(new Error('Invalid JSON: ' + data.slice(0,200))) }});
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

// ═══ URL CHECKER (existing) ═══
function fetchUrl(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept': 'text/html,*/*', 'Accept-Language': 'en-US,en;q=0.9' }, timeout: timeoutMs }, (res) => {
      let body = ''; let size = 0;
      res.setEncoding('utf8');
      res.on('data', c => { size += c.length; if (size < 200000) body += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject); req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

async function fetchWithRedirects(url, max = 3) {
  let cur = url;
  for (let i = 0; i <= max; i++) {
    const res = await fetchUrl(cur);
    if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
      let loc = res.headers.location;
      if (loc.startsWith('/')) { const u = new URL(cur); loc = u.origin + loc; }
      return { ...res, finalUrl: cur, redirected: true, redirectStatusCode: res.statusCode };
    }
    return { ...res, finalUrl: cur, redirected: false };
  }
}

async function checkSite(site, username) {
  const url = site.uri_check.replace('{account}', encodeURIComponent(username));
  const result = { name: site.name, url, cat: site.cat, status: 'not-found', error: null };
  try {
    const res = await fetchWithRedirects(url);
    const code = res.statusCode, body = res.body || '';
    if (site.m_code && code === site.m_code) return result;
    if (res.redirected && site.m_code && res.redirectStatusCode === site.m_code) return result;
    if (site.m_string && body.includes(site.m_string)) return result;
    if ((code === site.e_code) && (site.e_string ? body.includes(site.e_string) : true)) result.status = 'found';
  } catch (e) { result.status = 'error'; result.error = e.message; }
  return result;
}

// ═══ SSE SCAN ═══
app.get('/api/scan/:username', (req, res) => {
  const username = req.params.username;
  if (!username || username.length < 2 || username.length > 64) return res.status(400).json({ error: 'Invalid' });
  const catFilter = req.query.cat || 'all';
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  let filtered = catFilter === 'all' ? SITES : SITES.filter(s => s.cat === catFilter);
  const total = filtered.length; let completed = 0, found = 0, closed = false;
  res.on('close', () => { closed = true; });
  res.write(`data: ${JSON.stringify({ type: 'init', total, username })}\n\n`);
  const CONC = 15; let queue = [...filtered];
  async function go() {
    while (queue.length > 0 && !closed) {
      const batch = queue.splice(0, CONC);
      const results = await Promise.allSettled(batch.map(s => checkSite(s, username)));
      for (const r of results) {
        if (closed) return; completed++;
        const val = r.status === 'fulfilled' ? r.value : { name: '?', status: 'error', error: r.reason?.message };
        if (val.status === 'found') found++;
        res.write(`data: ${JSON.stringify({ type: 'result', ...val, progress: completed, total, found })}\n\n`);
      }
    }
    if (!closed) { res.write(`data: ${JSON.stringify({ type: 'done', total: completed, found })}\n\n`); res.end(); }
  }
  go().catch(e => { if (!closed) { res.write(`data: ${JSON.stringify({ type: 'error', message: e.message })}\n\n`); res.end(); }});
});

app.get('/api/stats', (req, res) => {
  const cats = [...new Set(SITES.map(s => s.cat))].sort();
  res.json({ totalSites: SITES.length, categories: cats });
});

app.listen(PORT, () => console.log(`THIS YOU? OSINT — port ${PORT} — ${SITES.length} sites`));
