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
      connectSrc: ["'self'", "https://search4faces.com"],
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

app.get('/api/scan/:username', globalLimiter, (req, res) => {
  const username = sanitize(req.params.username, 64);
  if (!isValidUsername(username)) return res.status(400).json({ error: 'Username invalide (lettres, chiffres, . _ - uniquement)' });
  const catFilter = sanitize(req.query.cat || 'all', 30);
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  let filtered = catFilter === 'all' ? SITES : SITES.filter(s => s.cat === catFilter);
  const total = filtered.length; let completed = 0, found = 0, closed = false;
  res.on('close', () => { closed = true; clearInterval(pingInterval); });
  res.write(`data: ${JSON.stringify({ type: 'init', total, username })}\n\n`);
  // Ping toutes les 15s pour garder la connexion vivante (écran qui s'éteint)
  const pingInterval = setInterval(() => {
    if (!closed) res.write(`: ping\n\n`);
  }, 15000);
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
    if (!closed) {
      clearInterval(pingInterval);
      res.write(`data: ${JSON.stringify({ type: 'done', total: completed, found })}\n\n`);
      res.end();
    }
  }
  go().catch(e => {
    clearInterval(pingInterval);
    if (!closed) { res.write(`data: ${JSON.stringify({ type: 'error', message: 'Erreur serveur' })}\n\n`); res.end() }
  });
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
  const args = ['-h', url, '-Cgidirs', 'all', '-nointeractive', '-timeout', '10', '-maxtime', '30'];
  execFile('nikto', args, { timeout: 35000, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
    const output = (stdout || '') + (stderr || '');
    if (!output && err) return res.json({ success: false, error: 'Nikto injoignable — ' + (err.message || '') });
    try {
      const vulns = [];
      const lines = output.split('\n');
      for (const line of lines) {
        if (line.startsWith('+ ') && !line.includes('Target IP') && !line.includes('Target Port') && !line.includes('Start Time') && !line.includes('Server:')) {
          vulns.push({ id: '?', uri: '', method: 'GET', msg: line.replace(/^\+ /, '').trim() });
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
    // Injectable seulement si SQLMap le confirme explicitement
    if (output.includes('is vulnerable') || output.match(/Parameter:[\s\S]+?Type:/)) injectable = true;
    const vulns = [];
    const paramMatches = [...output.matchAll(/Parameter:\s*(.+?)\s*\((.+?)\)/g)];
    paramMatches.forEach(m => vulns.push({ param: m[1], type: m[2] }));
    // Types seulement si injection confirmée
    const injTypes = [];
    if (injectable) {
      ['boolean-based blind','time-based blind','error-based','UNION query','stacked queries'].forEach(t => {
        if (output.toLowerCase().includes(t)) injTypes.push(t);
      });
    }
    res.json({ success: true, data: { url: cleanUrl, injectable, dbms, vulns, injTypes } });
  });
});

// ═══ SCAN APPROFONDI PSEUDO ═══
app.get('/api/deepscan/username/:username', heavyLimiter, async (req, res) => {
  const username = sanitize(req.params.username, 64);
  if (!isValidUsername(username)) return res.json({ success: false, error: 'Username invalide' });

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  const send = (type, data) => res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);

  send('start', { username });

  const checks = [
    // GitHub
    async () => {
      try {
        const r = await httpGet(`https://api.github.com/users/${encodeURIComponent(username)}`, 6000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body);
          return { source: 'GitHub', found: true, url: d.html_url, data: {
            nom: d.name, bio: d.bio, localisation: d.location, email: d.email,
            repos: d.public_repos, followers: d.followers, créé: d.created_at?.split('T')[0],
            blog: d.blog, entreprise: d.company, twitter: d.twitter_username
          }};
        }
      } catch(e) {}
      return { source: 'GitHub', found: false };
    },
    // Reddit
    async () => {
      try {
        const r = await httpGet(`https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`, 6000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body).data;
          return { source: 'Reddit', found: true, url: `https://reddit.com/u/${username}`, data: {
            karma: d.link_karma + d.comment_karma, créé: new Date(d.created_utc*1000).toISOString().split('T')[0],
            vérifié: d.verified, premium: d.is_gold
          }};
        }
      } catch(e) {}
      return { source: 'Reddit', found: false };
    },
    // Keybase
    async () => {
      try {
        const r = await httpGet(`https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(username)}`, 6000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body);
          if (d.them && d.them.length > 0) {
            const u = d.them[0];
            const proofs = u.proofs_summary?.all || [];
            return { source: 'Keybase', found: true, url: `https://keybase.io/${username}`, data: {
              nom: u.profile?.full_name, bio: u.profile?.bio, localisation: u.profile?.location,
              preuves: proofs.map(p => `${p.proof_type}: ${p.nametag}`).join(', ')
            }};
          }
        }
      } catch(e) {}
      return { source: 'Keybase', found: false };
    },
    // DEV.to
    async () => {
      try {
        const r = await httpGet(`https://dev.to/api/users/by_username?url=${encodeURIComponent(username)}`, 6000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body);
          return { source: 'DEV.to', found: true, url: `https://dev.to/${username}`, data: {
            nom: d.name, bio: d.summary, twitter: d.twitter_username, github: d.github_username,
            articles: d.articles_count
          }};
        }
      } catch(e) {}
      return { source: 'DEV.to', found: false };
    },
    // HackerNews
    async () => {
      try {
        const r = await httpGet(`https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(username)}.json`, 6000);
        if (r.statusCode === 200 && r.body !== 'null') {
          const d = JSON.parse(r.body);
          return { source: 'HackerNews', found: true, url: `https://news.ycombinator.com/user?id=${username}`, data: {
            karma: d.karma, créé: new Date(d.created*1000).toISOString().split('T')[0], about: d.about?.replace(/<[^>]+>/g,'').slice(0,150)
          }};
        }
      } catch(e) {}
      return { source: 'HackerNews', found: false };
    },
    // Gravatar
    async () => {
      try {
        const crypto2 = require('crypto');
        const md5 = crypto2.createHash('md5').update(username.toLowerCase()).digest('hex');
        const r = await httpGet(`https://www.gravatar.com/${md5}.json`, 5000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body).entry?.[0];
          if (d) return { source: 'Gravatar', found: true, url: `https://gravatar.com/${username}`, data: {
            nom: d.displayName, email: d.emails?.[0]?.value, bio: d.aboutMe, localisation: d.currentLocation
          }};
        }
      } catch(e) {}
      return { source: 'Gravatar', found: false };
    },
    // GitLab
    async () => {
      try {
        const r = await httpGet(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`, 6000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body);
          if (d.length > 0) return { source: 'GitLab', found: true, url: d[0].web_url, data: {
            nom: d[0].name, bio: d[0].bio, localisation: d[0].location, repos: d[0].public_repos
          }};
        }
      } catch(e) {}
      return { source: 'GitLab', found: false };
    },
    // crt.sh domaines
    async () => {
      try {
        const r = await httpGet(`https://crt.sh/?q=${encodeURIComponent(username)}&output=json`, 7000);
        if (r.statusCode === 200) {
          const d = JSON.parse(r.body);
          const domains = [...new Set(d.map(c => c.common_name).filter(n => n && !n.startsWith('*')))].slice(0, 10);
          if (domains.length) return { source: 'crt.sh (domaines)', found: true, url: `https://crt.sh/?q=${username}`, data: {
            domaines: domains.join(', ')
          }};
        }
      } catch(e) {}
      return { source: 'crt.sh (domaines)', found: false };
    },
    // Pastebin mentions
    async () => {
      try {
        const r = await searchDDG(`site:pastebin.com "${username}"`, 5);
        if (r.length) return { source: 'Pastebin', found: true, url: `https://pastebin.com/search?q=${encodeURIComponent(username)}`, data: {
          mentions: r.map(x => x.title).join(' | ')
        }};
      } catch(e) {}
      return { source: 'Pastebin', found: false };
    },
    // Web mentions
    async () => {
      try {
        const r = await searchDDG(`"${username}"`, 8);
        if (r.length) return { source: 'Web (DuckDuckGo)', found: true, data: { résultats: r.length, liens: r.map(x=>x.url).join(' | ') }};
      } catch(e) {}
      return { source: 'Web', found: false };
    },
  ];

  for (const check of checks) {
    try {
      const result = await check();
      send('result', result);
    } catch(e) {}
  }

  send('done', { total: checks.length });
  res.end();
});

// ═══ SCAN APPROFONDI EMAIL ═══
app.get('/api/deepscan/email/:email', heavyLimiter, async (req, res) => {
  const email = sanitize(req.params.email, 254).toLowerCase();
  if (!isValidEmail(email)) return res.json({ success: false, error: 'Email invalide' });
  const [user, domain] = email.split('@');
  const md5 = crypto.createHash('md5').update(email).digest('hex');

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  const send = (type, data) => res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
  send('start', { email });

  // Plateformes à tester avec l'email (via reset password ou API)
  const platforms = [
    { name: 'Gravatar', check: async () => {
      const r = await httpGet(`https://www.gravatar.com/avatar/${md5}?d=404`, 4000);
      if (r.statusCode === 200) {
        let profile = null;
        try { const gp = await httpGet(`https://www.gravatar.com/${md5}.json`, 4000); if (gp.statusCode===200) profile=JSON.parse(gp.body).entry?.[0]; } catch(e){}
        return { found: true, url: `https://gravatar.com/${user}`, data: { avatar: `https://www.gravatar.com/avatar/${md5}?s=100`, nom: profile?.displayName, bio: profile?.aboutMe }};
      }
      return { found: false };
    }},
    { name: 'GitHub (email)', check: async () => {
      const r = await httpGet(`https://api.github.com/search/users?q=${encodeURIComponent(email)}+in:email`, 6000);
      if (r.statusCode === 200) {
        const d = JSON.parse(r.body);
        if (d.total_count > 0) return { found: true, url: d.items[0].html_url, data: { login: d.items[0].login, total: d.total_count }};
      }
      return { found: false };
    }},
    { name: 'Fuites (LeakCheck)', check: async () => {
      const r = await httpGet(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`, 6000);
      if (r.statusCode === 200) {
        const d = JSON.parse(r.body);
        if (d.success && d.sources?.length) return { found: true, data: { fuites: d.sources.map(s=>s.name).join(', '), nombre: d.sources.length }};
      }
      return { found: false };
    }},
    { name: 'crt.sh (domaine)', check: async () => {
      const r = await httpGet(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 7000);
      if (r.statusCode === 200) {
        const d = JSON.parse(r.body);
        const subdomains = [...new Set(d.map(c=>c.common_name).filter(n=>n&&!n.startsWith('*')))].slice(0,8);
        if (subdomains.length) return { found: true, url: `https://crt.sh/?q=${domain}`, data: { 'sous-domaines': subdomains.join(', ') }};
      }
      return { found: false };
    }},
    { name: 'Web (mentions)', check: async () => {
      const r = await searchDDG(`"${email}"`, 8);
      if (r.length) return { found: true, data: { résultats: r.length, liens: r.slice(0,5).map(x=>x.url).join(' | ') }};
      return { found: false };
    }},
    { name: 'Pastebin', check: async () => {
      const r = await searchDDG(`site:pastebin.com "${email}"`, 5);
      if (r.length) return { found: true, url: r[0].url, data: { mentions: r.length, exemple: r[0].title }};
      return { found: false };
    }},
    { name: 'GitHub commits', check: async () => {
      const r = await httpGet(`https://api.github.com/search/commits?q=author-email:${encodeURIComponent(email)}&per_page=3`, 6000);
      if (r.statusCode === 200) {
        const d = JSON.parse(r.body);
        if (d.total_count > 0) return { found: true, data: { commits: d.total_count, exemple: d.items[0]?.html_url }};
      }
      return { found: false };
    }},
    { name: 'WHOIS (domaine)', check: async () => {
      const r = await httpGet(`https://www.whois.com/whois/${encodeURIComponent(domain)}`, 6000);
      if (r.statusCode === 200 && r.body.includes(email)) return { found: true, url: `https://www.whois.com/whois/${domain}`, data: { info: 'Email trouvé dans les données WHOIS du domaine' }};
      return { found: false };
    }},
  ];

  for (const p of platforms) {
    try {
      const result = await p.check();
      send('result', { source: p.name, ...result });
    } catch(e) {
      send('result', { source: p.name, found: false });
    }
  }

  send('done', { total: platforms.length });
  res.end();
});

// ═══ REVERSE IMAGE SEARCH ═══
app.post('/api/reverse-image', heavyLimiter, async (req, res) => {
  const { image } = req.body;
  if (!image || typeof image !== 'string') return res.json({ success: false, error: 'Image manquante' });
  if (image.length > 5 * 1024 * 1024) return res.json({ success: false, error: 'Image trop lourde' });

  const results = [];

  // FaceCheck.id — API publique gratuite
  try {
    const boundary = '----FormBoundary' + Date.now();
    const imgBuffer = Buffer.from(image, 'base64');
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="images"; filename="photo.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
      imgBuffer,
      Buffer.from(`\r\n--${boundary}--\r\n`)
    ]);
    const fcRes = await new Promise((resolve, reject) => {
      const req2 = https.request({
        hostname: 'facecheck.id', port: 443, path: '/api/upload_pic',
        method: 'POST',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length, 'Accept': 'application/json' },
        timeout: 15000
      }, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve(d)); });
      req2.on('error', reject); req2.on('timeout', () => { req2.destroy(); reject(new Error('timeout')); });
      req2.write(body); req2.end();
    });
    const fcData = JSON.parse(fcRes);
    if (fcData && fcData.id) {
      // Lancer la recherche
      const searchRes = await new Promise((resolve, reject) => {
        const payload = JSON.stringify({ id_search: fcData.id, with_progress: false });
        const req3 = https.request({
          hostname: 'facecheck.id', port: 443, path: '/api/search',
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
          timeout: 20000
        }, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve(d)); });
        req3.on('error', reject); req3.on('timeout', () => { req3.destroy(); reject(new Error('timeout')); });
        req3.write(payload); req3.end();
      });
      const srData = JSON.parse(searchRes);
      if (srData.output?.items?.length) {
        results.push({
          source: 'FaceCheck.id',
          found: true,
          items: srData.output.items.slice(0, 10).map(item => ({
            url: item.url, score: item.score,
            thumb: item.base64 ? `data:image/jpeg;base64,${item.base64}` : null
          }))
        });
      }
    }
  } catch(e) { results.push({ source: 'FaceCheck.id', found: false, error: e.message }); }

  res.json({ success: true, data: results });
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

// ═══ EXIFTOOL — LECTURE ═══
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 20 } });

app.post('/api/exif/read', upload.array('photos', 20), async (req, res) => {
  if (!req.files || !req.files.length) return res.json({ success: false, error: 'Aucun fichier reçu' });
  const os2 = require('os');
  const results = [];
  const tmpFiles = [];
  try {
    for (const file of req.files) {
      const tmpPath = path.join(os2.tmpdir(), 'exif_' + Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_'));
      fs.writeFileSync(tmpPath, file.buffer);
      tmpFiles.push(tmpPath);
    }
    await new Promise((resolve, reject) => {
      execFile('exiftool', ['-json', '-n', ...tmpFiles], { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
        try {
          const data = JSON.parse(stdout || '[]');
          data.forEach((d, i) => results.push({ filename: req.files[i]?.originalname || 'photo', data: d }));
          resolve();
        } catch(e) { reject(e); }
      });
    });
  } catch(e) {
    return res.json({ success: false, error: 'Erreur ExifTool : ' + e.message });
  } finally {
    tmpFiles.forEach(f => { try { fs.unlinkSync(f) } catch(e) {} });
  }
  // Calculer récurrences
  const freq = {};
  results.forEach(r => {
    Object.entries(r.data).forEach(([k, v]) => {
      if (k === 'SourceFile') return;
      const val = String(v);
      if (!freq[k]) freq[k] = {};
      freq[k][val] = (freq[k][val] || 0) + 1;
    });
  });
  const recurring = Object.entries(freq)
    .filter(([k, vals]) => Object.values(vals).some(c => c > 1))
    .map(([k, vals]) => ({ key: k, values: vals }))
    .sort((a, b) => Math.max(...Object.values(b.values)) - Math.max(...Object.values(a.values)));
  res.json({ success: true, data: { files: results, recurring, total: results.length } });
});

// ═══ EXIFTOOL — ÉDITION ═══
app.post('/api/exif/edit', upload.single('photo'), async (req, res) => {
  if (!req.file) return res.json({ success: false, error: 'Aucun fichier reçu' });
  const stripAll = req.body.stripAll === '1';
  const os2 = require('os');
  const ext = path.extname(req.file.originalname);
  const tmpIn = path.join(os2.tmpdir(), 'exif_in_' + Date.now() + '_' + req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_'));
  const tmpOut = tmpIn + '_out' + ext;
  try {
    fs.writeFileSync(tmpIn, req.file.buffer);
    let tagArgs;
    if (stripAll) {
      // Supprimer toutes les métadonnées
      tagArgs = ['-all=', '-tagsfromfile', '@', '-ICC_Profile', '-o', tmpOut, tmpIn];
    } else {
      const { tags } = req.body;
      if (!tags) return res.json({ success: false, error: 'Tags manquants' });
      let parsedTags;
      try { parsedTags = JSON.parse(tags); } catch(e) { return res.json({ success: false, error: 'Tags invalides' }); }
      // Valeur vide = supprimer le tag, valeur non vide = modifier
      tagArgs = Object.entries(parsedTags).map(([k, v]) => v === '' ? `-${k}=` : `-${k}=${v}`);
      tagArgs.push('-o', tmpOut, tmpIn);
    }
    await new Promise((resolve, reject) => {
      execFile('exiftool', tagArgs, { timeout: 15000 }, (err, stdout, stderr) => {
        if (err && !fs.existsSync(tmpOut)) reject(new Error(stderr || err.message));
        else resolve();
      });
    });
    if (!fs.existsSync(tmpOut)) return res.json({ success: false, error: 'ExifTool n\'a pas produit de fichier de sortie' });
    const editedBuffer = fs.readFileSync(tmpOut);
    res.setHeader('Content-Disposition', `attachment; filename="clean_${req.file.originalname}"`);
    res.setHeader('Content-Type', req.file.mimetype || 'application/octet-stream');
    res.send(editedBuffer);
  } catch(e) {
    res.json({ success: false, error: 'Erreur édition : ' + e.message });
  } finally {
    try { fs.unlinkSync(tmpIn) } catch(e) {}
    try { fs.unlinkSync(tmpOut) } catch(e) {}
  }
});

app.use((req, res) => { res.status(404).json({ error: 'Not found' }) });
app.use((err, req, res, next) => { console.error('Server error:', err.message); res.status(500).json({ error: 'Erreur interne' }); });

app.listen(PORT, '0.0.0.0', () => console.log(`THIS YOU? OSINT [SECURED] — port ${PORT} — ${SITES.length} sites`));
