const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const { execFile } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://www.gravatar.com", "https://search4faces.com", "https://*.userapi.com"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, 'https://' + req.hostname + req.url);
  }
  next();
});

app.set('trust proxy', 1);

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Trop de requêtes. Réessayez dans 15 minutes.' },
  keyGenerator: (req) => req.ip || 'unknown', validate: false,
});
app.use('/api/', globalLimiter);

const heavyLimiter = rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Maximum 5 scans par minute. Patientez.' }, validate: false });
const faceLimiter = rateLimit({ windowMs: 60 * 1000, max: 3, message: { error: 'Maximum 3 recherches faciales par minute.' }, validate: false });

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true }));
app.disable('x-powered-by');

function sanitize(str, maxLen = 100) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'`;\\{}()]/g, '').trim().slice(0, maxLen);
}
function isValidUsername(u) { return /^[a-zA-Z0-9._\-]{2,64}$/.test(u); }
function isValidEmail(e) { return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(e) && e.length <= 254; }
function isValidPhone(p) { return /^\+?[0-9\s\-()]{6,20}$/.test(p); }
function isValidIP(t) { return /^[a-zA-Z0-9.\-:]{2,253}$/.test(t); }

const SITES = JSON.parse(fs.readFileSync(path.join(__dirname, 'wmn-data.json'), 'utf8'));

function httpGet(url, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/json,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      timeout,
    }, res => {
      let body = ''; let sz = 0;
      res.setEncoding('utf8');
      res.on('data', c => { sz += c.length; if (sz < 300000) body += c; else req.destroy(); });
      res.on('end', () => resolve({ statusCode: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function httpsPost(hostname, urlpath, body, headers = {}, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    if (data.length > 5 * 1024 * 1024) return reject(new Error('Payload too large'));
    const opts = { hostname, port: 443, path: urlpath, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers }, timeout };
    const req = https.request(opts, res => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)) } catch (e) { resolve({ raw: d }) } }) });
    req.on('error', reject); req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(data); req.end();
  });
}

async function searchDDG(query, max = 6) {
  const results = [];
  try {
    const r = await httpGet(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, 6000);
    const ms = [...r.body.matchAll(/<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)<\/a>/gs)];
    for (const m of ms.slice(0, max)) {
      const url = m[1], title = m[2].replace(/<[^>]+>/g, '');
      if (url && title && url.startsWith('http')) results.push({ url, title });
    }
  } catch (e) { }
  return results;
}

// ═══ PHONE ═══
app.get('/api/phone/:number', heavyLimiter, async (req, res) => {
  try {
    const raw = sanitize(req.params.number, 25).replace(/[^\d+]/g, '');
    if (!isValidPhone(raw)) return res.json({ success: false, error: 'Numéro invalide. Format: +33612345678' });
    const num = raw.startsWith('+') ? raw : '+' + raw;
    const phone = parsePhoneNumberFromString(num);
    if (!phone) return res.json({ success: false, error: 'Numéro non reconnu' });
    const result = {
      international: phone.formatInternational(), national: phone.formatNational(),
      e164: phone.format('E.164'), country: phone.country || '?', type: phone.getType() || 'inconnu',
      valid: phone.isValid(), possible: phone.isPossible(),
    };
    const searches = [];
    for (const fmt of [result.international, result.e164, result.e164.replace('+', '')]) {
      const sr = await searchDDG(`"${fmt}"`);
      for (const s of sr) { if (!searches.find(x => x.url === s.url)) searches.push({ ...s, query: fmt }); }
    }
    result.searches = searches.slice(0, 12);
    res.json({ success: true, data: result });
  } catch (e) { res.json({ success: false, error: 'Erreur serveur' }); }
});

// ═══ EMAIL ═══
app.get('/api/email/:email', heavyLimiter, async (req, res) => {
  try {
    const email = sanitize(req.params.email, 254).toLowerCase();
    if (!isValidEmail(email)) return res.json({ success: false, error: 'Email invalide' });
    const [user, domain] = email.split('@');
    const md5 = crypto.createHash('md5').update(email).digest('hex');

    let hasGravatar = false;
    try { const g = await httpGet(`https://www.gravatar.com/avatar/${md5}?d=404`, 4000); hasGravatar = g.statusCode === 200 } catch (e) { }

    let gravatarProfile = null;
    try { const gp = await httpGet(`https://www.gravatar.com/${md5}.json`, 4000); if (gp.statusCode === 200) gravatarProfile = JSON.parse(gp.body).entry?.[0] || null } catch (e) { }

    // LeakCheck — gratuit, sans clé
    let breaches = [];
    try {
      const lc = await httpGet(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`, 6000);
      if (lc.statusCode === 200 && lc.body) {
        const lcData = JSON.parse(lc.body);
        if (lcData.success && lcData.sources) {
          breaches = lcData.sources.map(s => ({ name: s.name, date: s.date || '', count: s.records || 0 }));
        }
      }
    } catch (e) { }

    const searches = await searchDDG(`"${email}"`, 8);

    res.json({
      success: true, data: {
        email, user, domain, md5,
        gravatarUrl: hasGravatar ? `https://www.gravatar.com/avatar/${md5}?s=200` : null,
        hasGravatar, gravatarProfile, breaches, breachCount: breaches.length, searches
      }
    });
  } catch (e) { res.json({ success: false, error: 'Erreur serveur' }); }
});

// ═══ IP ═══
app.get('/api/ip/:target', heavyLimiter, async (req, res) => {
  try {
    const target = sanitize(req.params.target, 253);
    if (!isValidIP(target)) return res.json({ success: false, error: 'IP/domaine invalide' });
    const r = await httpGet(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=66846719`, 6000);
    const geo = JSON.parse(r.body);
    let ipinfo = null;
    try { const i = await httpGet(`https://ipinfo.io/${encodeURIComponent(target)}/json`, 5000); if (i.statusCode === 200) ipinfo = JSON.parse(i.body) } catch (e) { }
    let reverseDns = null;
    try { const dns = require('dns'); reverseDns = await new Promise((resolve, reject) => { dns.reverse(target, (err, h) => { if (err) resolve(null); else resolve(h) }) }) } catch (e) { }
    const searches = await searchDDG(`"${target}"`, 6);
    res.json({ success: true, data: { ...geo, ipinfo, reverseDns, searches, mapUrl: `https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}#map=13/${geo.lat}/${geo.lon}` } });
  } catch (e) { res.json({ success: false, error: 'Erreur serveur' }); }
});

// ═══ FACE ═══
app.post('/api/face-search', faceLimiter, async (req, res) => {
  const { image, source, results: maxR } = req.body;
  if (!image || typeof image !== 'string') return res.status(400).json({ error: 'No image' });
  if (image.length > 5 * 1024 * 1024) return res.status(400).json({ error: 'Image trop lourde (max 5MB)' });
  const validSources = ['vkok_avatar', 'vk_wall', 'vkokn_avatar', 'tt_avatar', 'ch_avatar', 'sb_photo'];
  const src = validSources.includes(source) ? source : 'vkok_avatar';
  try {
    const d1 = await httpsPost('search4faces.com', '/api/json-rpc/v1', { jsonrpc: '2.0', method: 'detectFaces', id: 'ty-' + Date.now(), params: { image } }, { Origin: 'https://search4faces.com', Referer: 'https://search4faces.com/en/vkok/index.html' });
    if (!d1.result?.faces?.length) return res.json({ success: false, message: 'Aucun visage détecté' });
    const d2 = await httpsPost('search4faces.com', '/api/json-rpc/v1', { jsonrpc: '2.0', method: 'searchFace', id: 'ty-' + Date.now(), params: { image: d1.result.image, face: d1.result.faces[0], source: src, hidden: true, results: Math.min(parseInt(maxR) || 50, 100).toString(), lang: 'en' } }, { Origin: 'https://search4faces.com', Referer: 'https://search4faces.com/en/vkok/index.html' });
    if (d2.result?.profiles) return res.json({ success: true, profiles: d2.result.profiles });
    return res.json({ success: false, message: d2.error?.message || 'Erreur API' });
  } catch (e) { return res.json({ success: false, message: 'Erreur serveur' }) }
});

// ═══ USERNAME SCAN (SSE) ═══
async function checkSite(site, username) {
  const url = site.uri_check.replace('{account}', encodeURIComponent(username));
  const result = { name: site.name, url, cat: site.cat, status: 'not-found', error: null };
  try {
    let cur = url;
    for (let i = 0; i < 3; i++) {
      const res = await httpGet(cur, 8000);
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        if (site.m_code && res.statusCode === site.m_code) return result;
        let loc = res.headers.location; if (loc.startsWith('/')) { const u = new URL(cur); loc = u.origin + loc }
        cur = loc; continue;
      }
      const code = res.statusCode, body = res.body || '';
      if (site.m_code && code === site.m_code) return result;
      if (site.m_string && body.includes(site.m_string)) return result;
      if ((code === site.e_code) && (site.e_string ? body.includes(site.e_string) : true)) result.status = 'found';
      break;
    }
  } catch (e) { result.status = 'error'; result.error = e.message } return result;
}

app.get('/api/scan/:username', heavyLimiter, (req, res) => {
  const username = sanitize(req.params.username, 64);
  if (!isValidUsername(username)) return res.status(400).json({ error: 'Username invalide (lettres, chiffres, . _ - uniquement)' });
  const catFilter = sanitize(req.query.cat || 'all', 30);
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  let filtered = catFilter === 'all' ? SITES : SITES.filter(s => s.cat === catFilter);
  const total = filtered.length; let completed = 0, found = 0, closed = false;
  res.on('close', () => { closed = true });
  res.write(`data: ${JSON.stringify({ type: 'init', total, username })}\n\n`);
  let queue = [...filtered];
  async function go() {
    while (queue.length > 0 && !closed) {
      const batch = queue.splice(0, 15);
      const results = await Promise.allSettled(batch.map(s => checkSite(s, username)));
      for (const r of results) {
        if (closed) return; completed++;
        const val = r.status === 'fulfilled' ? r.value : { name: '?', status: 'error', error: r.reason?.message };
        if (val.status === 'found') found++;
        res.write(`data: ${JSON.stringify({ type: 'result', ...val, progress: completed, total, found })}\n\n`);
      }
    }
    if (!closed) { res.write(`data: ${JSON.stringify({ type: 'done', total: completed, found })}\n\n`); res.end() }
  }
  go().catch(e => { if (!closed) { res.write(`data: ${JSON.stringify({ type: 'error', message: 'Erreur serveur' })}\n\n`); res.end() } });
});

app.get('/api/stats', (req, res) => {
  const cats = [...new Set(SITES.map(s => s.cat))].sort();
  res.json({ totalSites: SITES.length, categories: cats });
});

// ═══ NMAP ═══
const nmapLimiter = rateLimit({ windowMs: 60 * 1000, max: 3, message: { error: 'Maximum 3 scans nmap par minute.' }, validate: false });
app.get('/api/nmap/:target', nmapLimiter, async (req, res) => {
  const target = sanitize(req.params.target, 253);
  if (!isValidIP(target)) return res.json({ success: false, error: 'Cible invalide' });
  const args = ['-Pn', '--open', '-T3', '--host-timeout', '30s', '-oX', '-', target];
  execFile('nmap', args, { timeout: 35000, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
    if (err && !stdout) return res.json({ success: false, error: 'Nmap indisponible ou cible injoignable' });
    try {
      const ports = [];
      const portMatches = [...stdout.matchAll(/<port protocol="([^"]+)" portid="([^"]+)">.*?<state state="([^"]+)".*?<service name="([^"]*)"[^/]*(?:product="([^"]*)")?[^/]*(?:version="([^"]*)")?/gs)];
      for (const m of portMatches) {
        ports.push({ protocol: m[1], port: m[2], state: m[3], service: m[4] || '?', product: m[5] || '', version: m[6] || '' });
      }
      const osMatch = stdout.match(/<osmatch name="([^"]+)" accuracy="([^"]+)"/);
      const os = osMatch ? { name: osMatch[1], accuracy: osMatch[2] } : null;
      const latencyMatch = stdout.match(/rttvar=([0-9.]+)ms/);
      const latency = latencyMatch ? latencyMatch[1] + 'ms' : null;
      res.json({ success: true, data: { target, ports, os, latency, portCount: ports.length } });
    } catch (e) {
      res.json({ success: false, error: 'Erreur parsing résultats' });
    }
  });
});

// ═══ NIKTO ═══
const niktoLimiter = rateLimit({ windowMs: 60 * 1000, max: 2, message: { error: 'Maximum 2 scans nikto par minute.' }, validate: false });
app.get('/api/nikto/:target', niktoLimiter, async (req, res) => {
  const target = sanitize(req.params.target, 253);
  if (!isValidIP(target)) return res.json({ success: false, error: 'Cible invalide' });
  const url = target.startsWith('http') ? target : 'http://' + target;
  const args = ['-h', url, '-maxtime', '30s', '-nointeractive', '-Format', 'json', '-output', '-'];
  execFile('nikto', args, { timeout: 35000, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
    if (!stdout && err) return res.json({ success: false, error: 'Nikto indisponible ou cible injoignable' });
    try {
      const lines = stdout.split('\n').filter(l => l.trim().startsWith('{'));
      const vulns = [];
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          if (obj.vulnerabilities) {
            for (const v of obj.vulnerabilities) {
              vulns.push({
                id: v.id || '?',
                msg: v.msg || v.message || '?',
                uri: v.uri || '',
                method: v.method || 'GET',
                references: v.references || ''
              });
            }
          }
        } catch(e) {}
      }
      res.json({ success: true, data: { target, vulnCount: vulns.length, vulns } });
    } catch (e) {
      res.json({ success: false, error: 'Erreur parsing résultats' });
    }
  });
});

app.use((req, res) => { res.status(404).json({ error: 'Not found' }) });
app.use((err, req, res, next) => { console.error('Server error:', err.message); res.status(500).json({ error: 'Erreur interne' }); });

app.listen(PORT, () => console.log(`THIS YOU? OSINT [SECURED] — port ${PORT} — ${SITES.length} sites`));
