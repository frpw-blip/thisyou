const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { parsePhoneNumberFromString } = require('libphonenumber-js');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({limit:'10mb'}));
app.use(express.static(path.join(__dirname, 'public')));
const SITES = JSON.parse(fs.readFileSync(path.join(__dirname, 'wmn-data.json'), 'utf8'));

// ═══ HELPERS ═══
function httpGet(url, timeout=8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, {headers:{'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36','Accept':'text/html,application/json,*/*','Accept-Language':'en-US,en;q=0.9'},timeout}, res => {
      let body='';let sz=0;res.setEncoding('utf8');
      res.on('data',c=>{sz+=c.length;if(sz<500000)body+=c});
      res.on('end',()=>resolve({statusCode:res.statusCode,body,headers:res.headers}));
    });
    req.on('error',reject);req.on('timeout',()=>{req.destroy();reject(new Error('timeout'))});
  });
}
function httpsPost(hostname,urlpath,body,headers={},timeout=15000){
  return new Promise((resolve,reject)=>{
    const data=typeof body==='string'?body:JSON.stringify(body);
    const opts={hostname,port:443,path:urlpath,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data),...headers},timeout};
    const req=https.request(opts,res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d))}catch(e){resolve({raw:d})}})});
    req.on('error',reject);req.on('timeout',()=>{req.destroy();reject(new Error('timeout'))});
    req.write(data);req.end();
  });
}

// ═══ PHONE LOOKUP — REAL EMBEDDED RESULTS ═══
app.get('/api/phone/:number', async (req, res) => {
  try {
    const raw = req.params.number.replace(/[^\d+]/g,'');
    const num = raw.startsWith('+')?raw:'+'+raw;
    const phone = parsePhoneNumberFromString(num);
    if (!phone) return res.json({success:false,error:'Numéro invalide. Utilisez le format international: +33612345678'});
    
    const result = {
      raw, international: phone.formatInternational(), national: phone.formatNational(),
      e164: phone.format('E.164'), country: phone.country||'?', type: phone.getType()||'inconnu',
      valid: phone.isValid(), possible: phone.isPossible(),
      searches: [] // embedded search results
    };

    // Scrape Google for this number (3 formats)
    const formats = [result.international, result.e164, result.e164.replace('+','')];
    for (const fmt of formats) {
      try {
        const gUrl = `https://www.google.com/search?q=%22${encodeURIComponent(fmt)}%22&num=10`;
        const g = await httpGet(gUrl, 6000);
        // Extract snippets from Google HTML
        const matches = [...g.body.matchAll(/<div class="[^"]*"[^>]*><div[^>]*><div[^>]*><div[^>]*><a href="(\/url\?q=([^&"]+)[^"]*)"[^>]*><h3[^>]*>([^<]+)<\/h3>/g)];
        const altMatches = [...g.body.matchAll(/href="\/url\?q=(https?[^&"]+)[^"]*"[^>]*>.*?<h3[^>]*>(.*?)<\/h3>/gs)];
        const combined = altMatches.length > matches.length ? altMatches : matches;
        for (const m of combined.slice(0, 5)) {
          const url = decodeURIComponent(m[1]||m[2]||'');
          const title = (m[2]||m[3]||'').replace(/<[^>]+>/g,'');
          if (url && title && !result.searches.find(s=>s.url===url)) {
            result.searches.push({url, title, source:'Google', query:fmt});
          }
        }
      } catch(e) {}
    }

    // Try DuckDuckGo HTML (more scrape-friendly)
    try {
      const ddg = await httpGet(`https://html.duckduckgo.com/html/?q=%22${encodeURIComponent(result.international)}%22`, 6000);
      const ddgMatches = [...ddg.body.matchAll(/<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)<\/a>/gs)];
      for (const m of ddgMatches.slice(0, 5)) {
        const url = m[1];
        const title = m[2].replace(/<[^>]+>/g,'');
        if (url && title && !result.searches.find(s=>s.url===url)) {
          result.searches.push({url, title, source:'DuckDuckGo'});
        }
      }
    } catch(e) {}

    res.json({success:true, data:result});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ EMAIL OSINT — REAL EMBEDDED ═══
app.get('/api/email/:email', async (req, res) => {
  try {
    const email = req.params.email.toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json({success:false,error:'Email invalide'});
    const [user, domain] = email.split('@');
    const md5 = crypto.createHash('md5').update(email).digest('hex');
    
    // Gravatar
    let hasGravatar=false;
    try{const g=await httpGet(`https://www.gravatar.com/avatar/${md5}?d=404`,4000);hasGravatar=g.statusCode===200}catch(e){}
    
    // Gravatar profile JSON
    let gravatarProfile = null;
    try{const gp=await httpGet(`https://www.gravatar.com/${md5}.json`,4000);if(gp.statusCode===200){gravatarProfile=JSON.parse(gp.body).entry?.[0]||null}}catch(e){}
    
    // HIBP breaches
    let breaches=[];
    try{const h=await httpGet(`https://haveibeenpwned.com/api/v2/breachedaccount/${encodeURIComponent(email)}`,6000);if(h.statusCode===200&&h.body)breaches=JSON.parse(h.body).map(b=>({name:b.Name,date:b.BreachDate,count:b.PwnCount}))}catch(e){}

    // Google search for email
    let searches=[];
    try{
      const g=await httpGet(`https://html.duckduckgo.com/html/?q=%22${encodeURIComponent(email)}%22`,6000);
      const ms=[...g.body.matchAll(/<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)<\/a>/gs)];
      for(const m of ms.slice(0,8)){const url=m[1],title=m[2].replace(/<[^>]+>/g,'');if(url&&title)searches.push({url,title})}
    }catch(e){}

    res.json({success:true,data:{
      email,user,domain,md5,
      gravatarUrl:hasGravatar?`https://www.gravatar.com/avatar/${md5}?s=200`:null,
      hasGravatar, gravatarProfile,
      breaches, breachCount:breaches.length,
      searches
    }});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ IP / DOMAIN — REAL EMBEDDED ═══
app.get('/api/ip/:target', async (req, res) => {
  try {
    const target = req.params.target.trim();
    // ip-api.com (free, real data)
    const r = await httpGet(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=66846719`, 6000);
    const geo = JSON.parse(r.body);
    
    // ipinfo.io for extra data
    let ipinfo = null;
    try{const i=await httpGet(`https://ipinfo.io/${encodeURIComponent(target)}/json`,5000);if(i.statusCode===200)ipinfo=JSON.parse(i.body)}catch(e){}

    // Reverse DNS
    let reverseDns = null;
    try{const dns=require('dns');reverseDns=await new Promise((resolve,reject)=>{dns.reverse(target,(err,hostnames)=>{if(err)resolve(null);else resolve(hostnames)})})}catch(e){}

    // DuckDuckGo search
    let searches=[];
    try{
      const g=await httpGet(`https://html.duckduckgo.com/html/?q=%22${encodeURIComponent(target)}%22`,6000);
      const ms=[...g.body.matchAll(/<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.*?)<\/a>/gs)];
      for(const m of ms.slice(0,6)){const url=m[1],title=m[2].replace(/<[^>]+>/g,'');if(url&&title)searches.push({url,title})}
    }catch(e){}

    res.json({success:true,data:{
      ...geo, ipinfo, reverseDns, searches,
      mapUrl:`https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}#map=13/${geo.lat}/${geo.lon}`
    }});
  } catch(e) { res.json({success:false,error:e.message}); }
});

// ═══ FACE SEARCH PROXY ═══
app.post('/api/face-search', async (req, res) => {
  const {image,source,results:maxR}=req.body;if(!image)return res.status(400).json({error:'No image'});
  try{
    const d1=await httpsPost('search4faces.com','/api/json-rpc/v1',{jsonrpc:'2.0',method:'detectFaces',id:'ty-'+Date.now(),params:{image}},{Origin:'https://search4faces.com',Referer:'https://search4faces.com/en/vkok/index.html'});
    if(!d1.result?.faces?.length)return res.json({success:false,message:'Aucun visage détecté'});
    const d2=await httpsPost('search4faces.com','/api/json-rpc/v1',{jsonrpc:'2.0',method:'searchFace',id:'ty-'+Date.now(),params:{image:d1.result.image,face:d1.result.faces[0],source:source||'vkok_avatar',hidden:true,results:maxR||'50',lang:'en'}},{Origin:'https://search4faces.com',Referer:'https://search4faces.com/en/vkok/index.html'});
    if(d2.result?.profiles)return res.json({success:true,profiles:d2.result.profiles});
    return res.json({success:false,message:d2.error?.message||'Erreur API'});
  }catch(e){return res.json({success:false,message:e.message})}
});

// ═══ USERNAME SCAN (SSE) ═══
async function checkSite(site, username) {
  const url=site.uri_check.replace('{account}',encodeURIComponent(username));
  const result={name:site.name,url,cat:site.cat,status:'not-found',error:null};
  try{
    let cur=url;
    for(let i=0;i<3;i++){
      const res=await httpGet(cur,8000);
      if([301,302,303,307,308].includes(res.statusCode)&&res.headers.location){
        if(site.m_code&&res.statusCode===site.m_code)return result;
        let loc=res.headers.location;if(loc.startsWith('/')){const u=new URL(cur);loc=u.origin+loc}
        cur=loc;continue;
      }
      const code=res.statusCode,body=res.body||'';
      if(site.m_code&&code===site.m_code)return result;
      if(site.m_string&&body.includes(site.m_string))return result;
      if((code===site.e_code)&&(site.e_string?body.includes(site.e_string):true))result.status='found';
      break;
    }
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
