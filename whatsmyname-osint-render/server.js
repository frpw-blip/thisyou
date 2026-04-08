const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { parsePhoneNumberFromString, getCountryCallingCode } = require('libphonenumber-js');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({limit:'10mb'}));
app.use(express.static(path.join(__dirname, 'public')));
const SITES = JSON.parse(fs.readFileSync(path.join(__dirname, 'wmn-data.json'), 'utf8'));

// ═══ HELPERS ═══
function httpsGet(url, timeout=8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, {headers:{'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','Accept':'*/*'},timeout}, res => {
      let body='';let sz=0;res.setEncoding('utf8');
      res.on('data',c=>{sz+=c.length;if(sz<500000)body+=c});
      res.on('end',()=>resolve({statusCode:res.statusCode,body,headers:res.headers}));
    });
    req.on('error',reject);req.on('timeout',()=>{req.destroy();reject(new Error('timeout'))});
  });
}
function httpsPost(hostname,path,body,headers={},timeout=15000){
  return new Promise((resolve,reject)=>{
    const data=typeof body==='string'?body:JSON.stringify(body);
    const opts={hostname,port:443,path,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data),...headers},timeout};
    const req=https.request(opts,res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d))}catch(e){resolve({raw:d})}})});
    req.on('error',reject);req.on('timeout',()=>{req.destroy();reject(new Error('timeout'))});
    req.write(data);req.end();
  });
}
async function fetchWithRedirects(url, max=3) {
  let cur=url;
  for(let i=0;i<=max;i++){
    const res=await httpsGet(cur);
    if([301,302,303,307,308].includes(res.statusCode)&&res.headers.location){
      let loc=res.headers.location;
      if(loc.startsWith('/')){const u=new URL(cur);loc=u.origin+loc}
      return {...res,finalUrl:cur,redirected:true,redirectStatusCode:res.statusCode};
    }
    return {...res,finalUrl:cur,redirected:false};
  }
}

// ═══ PHONE LOOKUP ═══
app.get('/api/phone/:number', (req, res) => {
  try {
    const raw = req.params.number.replace(/[^\d+]/g,'');
    const phone = parsePhoneNumberFromString(raw.startsWith('+')?raw:'+'+raw);
    if (!phone) return res.json({success:false,error:'Numéro invalide'});
    const intl = phone.formatInternational();
    const national = phone.formatNational();
    const e164 = phone.format('E.164');
    const country = phone.country || '?';
    const type = phone.getType() || 'unknown';
    const valid = phone.isValid();
    const possible = phone.isPossible();
    // Google dorks
    const dorks = [
      {label:'Google',url:`https://www.google.com/search?q="${encodeURIComponent(intl)}"`},
      {label:'Google National',url:`https://www.google.com/search?q="${encodeURIComponent(national)}"`},
      {label:'Google E164',url:`https://www.google.com/search?q="${encodeURIComponent(e164)}"`},
      {label:'Google (no +)',url:`https://www.google.com/search?q="${encodeURIComponent(e164.replace('+',''))}"`},
      {label:'Google Social',url:`https://www.google.com/search?q="${encodeURIComponent(intl)}"+site:facebook.com+OR+site:linkedin.com+OR+site:twitter.com`},
      {label:'Google Annuaire',url:`https://www.google.com/search?q="${encodeURIComponent(intl)}"+annuaire+OR+pages+blanches+OR+yellow+pages`},
      {label:'Yandex',url:`https://yandex.com/search/?text="${encodeURIComponent(intl)}"`},
      {label:'DuckDuckGo',url:`https://duckduckgo.com/?q="${encodeURIComponent(intl)}"`},
    ];
    const externalTools = [
      {name:'Truecaller',url:'https://www.truecaller.com/'},
      {name:'Sync.me',url:'https://sync.me/'},
      {name:'NumLookup',url:'https://www.numlookup.com/'},
      {name:'SpyDialer',url:'https://www.spydialer.com/'},
      {name:'Infobel',url:'https://www.infobel.com/'},
      {name:'Whocalld',url:'https://whocalld.com/'},
      {name:'CallerID Test',url:'https://calleridtest.com/'},
    ];
    res.json({success:true,data:{raw,international:intl,national,e164,country,type,valid,possible,dorks,externalTools}});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ EMAIL OSINT ═══
app.get('/api/email/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json({success:false,error:'Email invalide'});
    const [user, domain] = email.split('@');
    const md5 = crypto.createHash('md5').update(email).digest('hex');
    const gravatarUrl = `https://www.gravatar.com/avatar/${md5}?d=404`;
    // Check gravatar
    let hasGravatar = false;
    try { const g = await httpsGet(gravatarUrl,5000); hasGravatar = g.statusCode === 200; } catch(e){}
    // Check HIBP (free API, limited)
    let breaches = [];
    try {
      const h = await httpsGet(`https://haveibeenpwned.com/api/v2/breachedaccount/${encodeURIComponent(email)}`,8000);
      if (h.statusCode === 200 && h.body) breaches = JSON.parse(h.body).map(b=>b.Name||b);
    } catch(e){}
    const dorks = [
      {label:'Google',url:`https://www.google.com/search?q="${encodeURIComponent(email)}"`},
      {label:'Google Social',url:`https://www.google.com/search?q="${encodeURIComponent(email)}"+site:facebook.com+OR+site:linkedin.com+OR+site:twitter.com`},
      {label:'Google Docs',url:`https://www.google.com/search?q="${encodeURIComponent(email)}"+filetype:pdf+OR+filetype:doc+OR+filetype:xls`},
      {label:'Google Pastes',url:`https://www.google.com/search?q="${encodeURIComponent(email)}"+site:pastebin.com+OR+site:ghostbin.com`},
      {label:'Yandex',url:`https://yandex.com/search/?text="${encodeURIComponent(email)}"`},
      {label:'DuckDuckGo',url:`https://duckduckgo.com/?q="${encodeURIComponent(email)}"`},
    ];
    const externalTools = [
      {name:'Have I Been Pwned',url:`https://haveibeenpwned.com/account/${encodeURIComponent(email)}`},
      {name:'Epieos',url:`https://epieos.com/?q=${encodeURIComponent(email)}`},
      {name:'Hunter.io',url:`https://hunter.io/email-verifier/${encodeURIComponent(email)}`},
      {name:'EmailRep',url:`https://emailrep.io/${encodeURIComponent(email)}`},
      {name:'Dehashed',url:'https://dehashed.com/'},
      {name:'IntelX',url:`https://intelx.io/?s=${encodeURIComponent(email)}`},
    ];
    res.json({success:true,data:{email,user,domain,gravatarUrl:hasGravatar?`https://www.gravatar.com/avatar/${md5}?s=200`:null,hasGravatar,breaches,breachCount:breaches.length,dorks,externalTools}});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ IP / DOMAIN LOOKUP ═══
app.get('/api/ip/:target', async (req, res) => {
  try {
    const target = req.params.target.trim();
    // IP geolocation via ip-api.com (free, 45/min)
    const r = await httpsGet(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query`,8000);
    const geo = JSON.parse(r.body);
    const dorks = [
      {label:'Google',url:`https://www.google.com/search?q="${encodeURIComponent(target)}"`},
      {label:'Shodan',url:`https://www.shodan.io/search?query=${encodeURIComponent(target)}`},
      {label:'Censys',url:`https://search.censys.io/hosts/${encodeURIComponent(target)}`},
      {label:'VirusTotal',url:`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(target)}`},
      {label:'AbuseIPDB',url:`https://www.abuseipdb.com/check/${encodeURIComponent(target)}`},
      {label:'SecurityTrails',url:`https://securitytrails.com/domain/${encodeURIComponent(target)}/dns`},
    ];
    const externalTools = [
      {name:'Shodan',url:`https://www.shodan.io/host/${encodeURIComponent(target)}`},
      {name:'Censys',url:`https://search.censys.io/hosts/${encodeURIComponent(target)}`},
      {name:'VirusTotal',url:`https://www.virustotal.com/gui/domain/${encodeURIComponent(target)}`},
      {name:'WHOIS',url:`https://who.is/whois/${encodeURIComponent(target)}`},
      {name:'DNSDumpster',url:'https://dnsdumpster.com/'},
      {name:'crt.sh',url:`https://crt.sh/?q=${encodeURIComponent(target)}`},
    ];
    res.json({success:true,data:{...geo,dorks,externalTools}});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ FACE SEARCH PROXY ═══
app.post('/api/face-search', async (req, res) => {
  const {image,source,results:maxR}=req.body;if(!image)return res.status(400).json({error:'No image'});
  try{
    const d1=await httpsPost('search4faces.com','/api/json-rpc/v1',{jsonrpc:'2.0',method:'detectFaces',id:'ty-'+Date.now(),params:{image}},{Origin:'https://search4faces.com',Referer:'https://search4faces.com/en/vkok/index.html'});
    if(!d1.result||!d1.result.faces||!d1.result.faces.length)return res.json({success:false,error:'no_faces',message:'Aucun visage détecté'});
    const d2=await httpsPost('search4faces.com','/api/json-rpc/v1',{jsonrpc:'2.0',method:'searchFace',id:'ty-'+Date.now(),params:{image:d1.result.image,face:d1.result.faces[0],source:source||'vkok_avatar',hidden:true,results:maxR||'50',lang:'en'}},{Origin:'https://search4faces.com',Referer:'https://search4faces.com/en/vkok/index.html'});
    if(d2.result&&d2.result.profiles)return res.json({success:true,profiles:d2.result.profiles});
    return res.json({success:false,error:'api_error',message:d2.error?.message||'Erreur API'});
  }catch(e){return res.json({success:false,error:'proxy_error',message:e.message})}
});

// ═══ USERNAME SCAN (SSE) ═══
async function checkSite(site, username) {
  const url=site.uri_check.replace('{account}',encodeURIComponent(username));
  const result={name:site.name,url,cat:site.cat,status:'not-found',error:null};
  try{
    const res=await fetchWithRedirects(url);const code=res.statusCode,body=res.body||'';
    if(site.m_code&&code===site.m_code)return result;
    if(res.redirected&&site.m_code&&res.redirectStatusCode===site.m_code)return result;
    if(site.m_string&&body.includes(site.m_string))return result;
    if((code===site.e_code)&&(site.e_string?body.includes(site.e_string):true))result.status='found';
  }catch(e){result.status='error';result.error=e.message}return result;
}
app.get('/api/scan/:username',(req,res)=>{
  const username=req.params.username;if(!username||username.length<2||username.length>64)return res.status(400).json({error:'Invalid'});
  const catFilter=req.query.cat||'all';
  res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});
  let filtered=catFilter==='all'?SITES:SITES.filter(s=>s.cat===catFilter);
  const total=filtered.length;let completed=0,found=0,closed=false;
  res.on('close',()=>{closed=true});
  res.write(`data: ${JSON.stringify({type:'init',total,username})}\n\n`);
  let queue=[...filtered];
  async function go(){while(queue.length>0&&!closed){const batch=queue.splice(0,15);const results=await Promise.allSettled(batch.map(s=>checkSite(s,username)));for(const r of results){if(closed)return;completed++;const val=r.status==='fulfilled'?r.value:{name:'?',status:'error',error:r.reason?.message};if(val.status==='found')found++;res.write(`data: ${JSON.stringify({type:'result',...val,progress:completed,total,found})}\n\n`)}}if(!closed){res.write(`data: ${JSON.stringify({type:'done',total:completed,found})}\n\n`);res.end()}}
  go().catch(e=>{if(!closed){res.write(`data: ${JSON.stringify({type:'error',message:e.message})}\n\n`);res.end()}});
});
app.get('/api/stats',(req,res)=>{const cats=[...new Set(SITES.map(s=>s.cat))].sort();res.json({totalSites:SITES.length,categories:cats})});

app.listen(PORT, ()=>console.log(`THIS YOU? OSINT — port ${PORT} — ${SITES.length} sites`));
