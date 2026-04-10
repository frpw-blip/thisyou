const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const { execFile, exec } = require('child_process');

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

// Trouver nikto au démarrage
let NIKTO_CMD = null;
exec('which nikto 2>/dev/null || find /usr -name "nikto.pl" 2>/dev/null | head -1', (err, stdout) => {
  const p = (stdout || '').trim().split('\n')[0];
  if (p) NIKTO_CMD = p;
  console.log('Nikto:', NIKTO_CMD || 'non trouvé');
});

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
  if (!NIKTO_CMD) return res.json({ success: false, error: 'Nikto non disponible sur ce serveur' });
  const isScript = NIKTO_CMD.endsWith('.pl');
  const cmd = isScript ? 'perl' : NIKTO_CMD;
  const args = isScript
    ? [NIKTO_CMD, '-h', url, '-maxtime', '30', '-nointeractive', '-Format', 'csv', '-output', '-']
    : ['-h', url, '-maxtime', '30', '-nointeractive', '-Format', 'csv', '-output', '-'];
  execFile(cmd, args, { timeout: 35000, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
    const output = stdout || '';
    if (!output && err) return res.json({ success: false, error: 'Nikto injoignable — ' + (err.message || '') });
    try {
      const vulns = [];
      const lines = output.split('\n').filter(l => l && !l.startsWith('#') && !l.startsWith('"Nikto'));
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length >= 7) {
          vulns.push({
            id: (parts[3] || '').replace(/"/g, '').trim(),
            uri: (parts[4] || '').replace(/"/g, '').trim(),
            method: (parts[5] || 'GET').replace(/"/g, '').trim(),
            msg: (parts[6] || '').replace(/"/g, '').trim(),
          });
        }
      }
      res.json({ success: true, data: { target, vulnCount: vulns.length, vulns } });
    } catch (e) {
      res.json({ success: false, error: 'Erreur parsing résultats' });
    }
  });
});

// ═══ JOHN THE RIPPER ═══
const johnLimiter = rateLimit({ windowMs: 60 * 1000, max: 3, message: { error: 'Maximum 3 tentatives par minute.' }, validate: false });
app.post('/api/crack', johnLimiter, async (req, res) => {
  const { hash, format } = req.body;
  if (!hash || typeof hash !== 'string') return res.json({ success: false, error: 'Hash manquant' });
  const cleanHash = hash.trim().replace(/[^a-fA-F0-9$./:\\*!@#%^&+=\[\]{}|<>?~`\-]/g, '').slice(0, 512);
  if (!cleanHash) return res.json({ success: false, error: 'Hash invalide' });
  const validFormats = ['raw-md5','raw-sha1','raw-sha256','raw-sha512','bcrypt','nt','raw-md4'];
  const fmt = validFormats.includes(format) ? format : 'raw-md5';
  const os2 = require('os');
  const tmpFile = path.join(os2.tmpdir(), 'john_' + Date.now() + '.txt');
  fs.writeFileSync(tmpFile, cleanHash + '\n');
  const wordlist = '/usr/share/john/rockyou.txt';
  execFile('john', ['--wordlist='+wordlist, '--format='+fmt, tmpFile], { timeout: 30000, maxBuffer: 1024 * 256 }, () => {
    execFile('john', ['--show', '--format='+fmt, tmpFile], { timeout: 5000 }, (err2, stdout2) => {
      try { fs.unlinkSync(tmpFile) } catch(e) {}
      const match = stdout2 && stdout2.match(/^[^:]+:(.+?)(?:\s*:\d+)?$/m);
      if (match && match[1]) return res.json({ success: true, found: true, password: match[1], hash: cleanHash, format: fmt });
      res.json({ success: true, found: false, hash: cleanHash, format: fmt });
    });
  });
});

// ═══ WEBINFO ═══
app.post('/api/webinfo', heavyLimiter, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.json({ success: false, error: 'URL manquante' });
  if (!url.startsWith('http://') && !url.startsWith('https://')) return res.json({ success: false, error: 'URL invalide' });
  try {
    const r = await httpGet(url, 8000);
    const headers = r.headers || {};
    const techs = [];
    if (headers['x-powered-by']) techs.push(headers['x-powered-by']);
    if (headers['server']) techs.push(headers['server']);
    const body = r.body || '';
    if (body.includes('wp-content')) techs.push('WordPress');
    if (body.includes('Drupal')) techs.push('Drupal');
    if (body.includes('Joomla')) techs.push('Joomla');
    if (body.includes('shopify')) techs.push('Shopify');
    if (body.includes('react')) techs.push('React');
    if (body.includes('vue.js') || body.includes('vue.min.js')) techs.push('Vue.js');
    if (body.includes('angular')) techs.push('Angular');
    if (body.includes('jquery')) techs.push('jQuery');
    if (body.includes('bootstrap')) techs.push('Bootstrap');
    if (headers['cf-ray']) techs.push('Cloudflare');
    if (headers['x-vercel-id']) techs.push('Vercel');
    if (headers['x-amz-request-id']) techs.push('AWS');
    const secHeaders = {};
    ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','x-xss-protection','referrer-policy'].forEach(h => {
      if (headers[h]) secHeaders[h] = headers[h];
    });
    res.json({ success: true, data: { url, status: r.statusCode, server: headers['server'] || '—', redirectUrl: headers['location'] || null, headers: secHeaders, techs: [...new Set(techs)] } });
  } catch (e) {
    res.json({ success: false, error: 'Impossible de joindre le site : ' + e.message });
  }
});

// ═══ SQLMAP ═══
const sqlmapLimiter = rateLimit({ windowMs: 60 * 1000, max: 2, message: { error: 'Maximum 2 scans SQLMap par minute.' }, validate: false });
app.post('/api/sqlmap', sqlmapLimiter, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.json({ success: false, error: 'URL manquante' });
  if (!url.startsWith('http://') && !url.startsWith('https://')) return res.json({ success: false, error: 'URL invalide' });
  const cleanUrl = url.trim().slice(0, 500);
  const args = ['/opt/sqlmap/sqlmap.py', '-u', cleanUrl, '--batch', '--level=1', '--risk=1', '--timeout=10', '--retries=1', '--output-dir=/tmp/sqlmap_out', '--disable-coloring'];
  execFile('python3', args, { timeout: 60000, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
    const output = (stdout || '') + (stderr || '');
    if (!output && err) return res.json({ success: false, error: 'SQLMap indisponible ou cible injoignable' });
    let injectable = false, dbms = null;
    const dbmsMatch = output.match(/back-end DBMS:\s*(.+)/i);
    if (dbmsMatch) dbms = dbmsMatch[1].trim();
    if (output.includes('is vulnerable') || output.includes('Parameter:')) injectable = true;
    const vulns = [];
    const paramMatches = [...output.matchAll(/Parameter:\s*(.+?)\s*\((.+?)\)/g)];
    paramMatches.forEach(m => vulns.push({ param: m[1], type: m[2] }));
    const injTypes = [];
    ['boolean-based blind','time-based blind','error-based','UNION query','stacked queries'].forEach(t => {
      if (output.toLowerCase().includes(t)) injTypes.push(t);
    });
    res.json({ success: true, data: { url: cleanUrl, injectable, dbms, vulns, injTypes } });
  });
});

// ═══ CVE / EXPLOITS ═══
app.post('/api/exploits', heavyLimiter, async (req, res) => {
  const { services } = req.body;
  if (!services || !Array.isArray(services)) return res.json({ success: false, error: 'Services manquants' });
  const results = [];
  for (const svc of services.slice(0, 5)) {
    const query = `${svc.service} ${svc.product || ''} ${svc.version || ''}`.trim();
    if (!query || query === '?') continue;
    try {
      const r = await httpGet(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=5`, 8000);
      if (r.statusCode === 200) {
        const data = JSON.parse(r.body);
        const cves = (data.vulnerabilities || []).map(v => ({
          id: v.cve.id,
          description: (v.cve.descriptions?.find(d => d.lang === 'en')?.value || '').slice(0, 200),
          severity: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || v.cve.metrics?.cvssMetricV2?.[0]?.baseSeverity || '?',
          score: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || v.cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null,
          metasploitUrl: `https://www.rapid7.com/db/search/?q=${encodeURIComponent(svc.service + ' ' + (svc.product || ''))}`,
          exploitdbUrl: `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}`,
        }));
        if (cves.length) results.push({ service: svc.service, product: svc.product, version: svc.version, port: svc.port, cves });
      }
    } catch(e) {}
  }
  res.json({ success: true, data: results });
});

app.use((req, res) => { res.status(404).json({ error: 'Not found' }) });
app.use((err, req, res, next) => { console.error('Server error:', err.message); res.status(500).json({ error: 'Erreur interne' }); });

app.listen(PORT, '0.0.0.0', () => console.log(`THIS YOU? OSINT [SECURED] — port ${PORT} — ${SITES.length} sites`));
