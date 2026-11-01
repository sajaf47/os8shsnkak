const express=require('express'),fs=require('fs'),cr=require('crypto'),http=require('http'),https=require('https'),{spawn,execSync}=require('child_process'),os=require('os'),qrg=require('qrcode-generator');
const D=process.env.DATA_DIR||'./data',F=D+'/db.json',X=D+'/xray.json';
fs.mkdirSync(D,{recursive:true});
const hex=n=>cr.randomBytes(n).toString('hex'),uid=()=>cr.randomUUID(),b64=s=>Buffer.from(s).toString('base64');
let xp;
const runX=()=>{if(xp)xp.kill();const p=spawn('xray',['run','-c',X],{stdio:'inherit'});xp=p;p.on('exit',()=>{if(xp===p)xp=null})};
const qs=()=>{try{return JSON.parse(execSync('xray api statsquery -s 127.0.0.1:10085 -reset',{timeout:5000}))}catch{return{}}};

// ---------- حالت نود (Agent) ----------
if(process.env.NODE_KEY){
  const a=express();a.use(express.json({limit:'5mb'}));
  a.use((q,r,n)=>q.headers['x-key']==process.env.NODE_KEY?n():r.sendStatus(403));
  a.post('/config',(q,r)=>{fs.writeFileSync(X,JSON.stringify(q.body));runX();r.json({ok:1})});
  a.get('/stats',(q,r)=>r.json(qs()));
  if(fs.existsSync(X))runX();
  a.listen(process.env.NODE_PORT||62050);return;
}

// ---------- دیتابیس ----------
let db={settings:{panelPort:2053,subPort:2096,domain:'',cert:'',key:'',pass:'',secret:hex(32)},inbounds:[],clients:[],nodes:[],mtproto:[],hist:[],log:[]};
if(fs.existsSync(F))db=Object.assign(db,JSON.parse(fs.readFileSync(F)));
const save=()=>fs.writeFileSync(F,JSON.stringify(db,null,1));

// ---------- ساخت کانفیگ Xray ----------
const xin=i=>{
  const cl=db.clients.filter(c=>c.on!==false&&(c.inb||[]).includes(i.id)),P=i.protocol;let s={};
  if(P=='vless')s={clients:cl.map(c=>({id:c.uuid,email:c.email,flow:i.flow||''})),decryption:'none'};
  else if(P=='vmess')s={clients:cl.map(c=>({id:c.uuid,email:c.email}))};
  else if(P=='trojan')s={clients:cl.map(c=>({password:c.uuid,email:c.email}))};
  else if(P=='shadowsocks')s={method:'chacha20-ietf-poly1305',network:'tcp,udp',clients:cl.map(c=>({password:c.uuid,email:c.email,method:'chacha20-ietf-poly1305'}))};
  else if(P=='socks'||P=='http')s={auth:'password',udp:true,accounts:cl.map(c=>({user:c.email,pass:c.uuid}))};
  else if(P=='wireguard')s={secretKey:i.wgPriv,mtu:1420,peers:cl.map(c=>({publicKey:c.wgPub,allowedIPs:[`10.66.0.${c.wgN}/32`]}))};
  else if(P=='dokodemo-door')s={address:i.target||'127.0.0.1',port:+i.tport||80,network:'tcp,udp'};
  const o={tag:'in-'+i.id,port:+i.port,listen:'0.0.0.0',protocol:P,settings:s,sniffing:{enabled:true,destOverride:['http','tls']}};
  if(['vless','vmess','trojan','shadowsocks'].includes(P)){
    const n=i.net||'tcp',st={network:n,security:i.sec||'none'},p=i.path||'/';
    if(n=='ws')st.wsSettings={path:p};if(n=='grpc')st.grpcSettings={serviceName:i.path||'grpc'};
    if(n=='httpupgrade')st.httpupgradeSettings={path:p};if(n=='xhttp')st.xhttpSettings={path:p};
    if(st.security=='tls')st.tlsSettings={serverName:i.sni||undefined,certificates:[{certificateFile:i.cert||db.settings.cert,keyFile:i.key||db.settings.key}]};
    if(st.security=='reality'){const d=i.sni||'www.microsoft.com';st.realitySettings={dest:d+':443',serverNames:[d],privateKey:i.priv,shortIds:[i.sid]}}
    o.streamSettings=st;
  }
  return o;
};
const build=nid=>({log:{loglevel:'warning'},stats:{},api:{tag:'api',services:['StatsService']},
  policy:{levels:{0:{statsUserUplink:true,statsUserDownlink:true}}},
  inbounds:[{tag:'api',listen:'127.0.0.1',port:10085,protocol:'dokodemo-door',settings:{address:'127.0.0.1'}},
    ...db.inbounds.filter(i=>i.on!==false&&(i.node||'local')==nid&&i.protocol!='hysteria2').map(xin)],
  outbounds:[{protocol:'freedom',tag:'direct'},{protocol:'blackhole',tag:'block'}],
  routing:{rules:[{type:'field',inboundTag:['api'],outboundTag:'api'}]}});
const gen=i=>{try{const o=execSync('xray x25519').toString();
  i.priv=/Private\s?Key:\s*(\S+)/i.exec(o)[1];i.pub=/(Public\s?Key|Password):\s*(\S+)/i.exec(o)[2];i.sid=hex(4)}catch(e){console.log('x25519 failed',e.message)}};

// ---------- نودها و پروکسی تلگرام ----------
const push=n=>fetch(`http://${n.address}:${n.port||62050}/config`,{method:'POST',headers:{'x-key':n.key,'content-type':'application/json'},body:JSON.stringify(build(n.id))}).then(()=>n.ok=1).catch(()=>n.ok=0);
const mp={};
const mt=()=>{for(const k in mp){mp[k].kill();delete mp[k]}
  db.mtproto.filter(m=>m.on!==false).forEach(m=>{mp[m.id]=spawn('mtg',['simple-run','0.0.0.0:'+m.port,m.secret],{stdio:'inherit'})})};
const wk=()=>{const k=cr.generateKeyPairSync('x25519');return{priv:k.privateKey.export({type:'pkcs8',format:'der'}).slice(-32).toString('base64'),pub:k.publicKey.export({type:'spki',format:'der'}).slice(-32).toString('base64')}};
const logA=t=>{db.log.unshift({t:Date.now(),m:t});db.log=db.log.slice(0,15)};
const hp2={};
const hy=()=>{for(const k in hp2){hp2[k].kill();delete hp2[k]}
  db.inbounds.filter(i=>i.protocol=='hysteria2'&&i.on!==false&&(i.node||'local')=='local').forEach((i,n)=>{
    i.sp=40000+n;const cl=db.clients.filter(c=>c.on!==false&&(c.inb||[]).includes(i.id)),f=`${D}/hy-${i.id}.yaml`;
    fs.writeFileSync(f,`listen: :${i.port}\ntls:\n  cert: ${i.cert||db.settings.cert}\n  key: ${i.key||db.settings.key}\nauth:\n  type: userpass\n  userpass:\n${cl.map(c=>`    "${c.email}": "${c.uuid}"`).join('\n')||'    x: x'}\ntrafficStats:\n  listen: 127.0.0.1:${i.sp}\n`);
    hp2[i.id]=spawn('hysteria',['server','-c',f],{stdio:'inherit'})})};
const apply=()=>{save();fs.writeFileSync(X,JSON.stringify(build('local')));runX();db.nodes.forEach(push);mt();hy()};

// ---------- لینک‌ها ----------
const links=c=>db.inbounds.filter(i=>i.on!==false&&(c.inb||[]).includes(i.id)).map(i=>{
  const nd=db.nodes.find(n=>n.id==i.node),h=(nd&&nd.address)||db.settings.domain||'SERVER_IP';
  const q=new URLSearchParams({type:i.net||'tcp',security:i.sec||'none'});
  if(i.path)q.set(i.net=='grpc'?'serviceName':'path',i.path);if(i.sni)q.set('sni',i.sni);if(i.flow)q.set('flow',i.flow);
  if(i.sec=='reality'){q.set('pbk',i.pub);q.set('sid',i.sid);q.set('fp','chrome')}
  const nm=i.remark+'-'+c.email,e=encodeURIComponent(nm);
  switch(i.protocol){
    case'vless':return`vless://${c.uuid}@${h}:${i.port}?${q}#${e}`;
    case'vmess':return'vmess://'+b64(JSON.stringify({v:2,ps:nm,add:h,port:+i.port,id:c.uuid,aid:0,net:i.net||'tcp',type:'none',host:'',path:i.path||'',tls:i.sec=='tls'?'tls':'',sni:i.sni||''}));
    case'trojan':return`trojan://${c.uuid}@${h}:${i.port}?${q}#${e}`;
    case'wireguard':return`wireguard://${encodeURIComponent(c.wgPriv)}@${h}:${i.port}?address=10.66.0.${c.wgN}/32&publickey=${encodeURIComponent(i.wgPub)}&mtu=1420#${e}`;
    case'hysteria2':return`hysteria2://${encodeURIComponent(c.email)}:${c.uuid}@${h}:${i.port}/?sni=${i.sni||h}#${e}`;
    case'shadowsocks':return`ss://${b64('chacha20-ietf-poly1305:'+c.uuid)}@${h}:${i.port}#${e}`;
  }return'';}).filter(Boolean);

// ---------- احراز هویت ----------
const sign=t=>cr.createHmac('sha256',db.settings.secret).update(t).digest('hex');
const cookie=r=>{const e=Date.now()+6048e5;r.setHeader('Set-Cookie',`ahb=${e}.${sign(''+e)};HttpOnly;Path=/;SameSite=Strict;Max-Age=604800`)};
const ok=r=>{const m=/ahb=([^;]+)/.exec(r.headers.cookie||'');if(!m)return false;const[e,s]=m[1].split('.');return +e>Date.now()&&s==sign(e)};
const hp=p=>{const s=hex(8);return s+':'+cr.scryptSync(p,s,32).toString('hex')};
const vp=(p,h)=>{const[s,x]=h.split(':'),y=cr.scryptSync(p,s,32).toString('hex');return x==y};

const app=express();app.use(express.json());const IDX=[__dirname+'/public/index.html',__dirname+'/index.html'].find(f=>fs.existsSync(f));
app.get('/',(q,r)=>r.sendFile(IDX));
app.get('/api/auth',(q,r)=>r.json({setup:!db.settings.pass,ok:ok(q)}));
app.post('/api/setup',(q,r)=>{const p=q.body.p;if(db.settings.pass||!p||p.length<6)return r.sendStatus(400);db.settings.pass=hp(p);save();cookie(r);r.json({ok:1})});
let cpuP=0,lc=os.cpus();
setInterval(()=>{const c=os.cpus();let i=0,t=0;c.forEach((x,n)=>{const a=lc[n].times,b=x.times;for(const k in b)t+=b[k]-a[k];i+=b.idle-a.idle});cpuP=t?Math.round((1-i/t)*100):0;lc=c},3000);
const sysInfo=()=>{let d={total:0,free:0};try{const s=fs.statfsSync(D);d={total:s.blocks*s.bsize,free:s.bavail*s.bsize}}catch{}
  return{cpu:cpuP,cores:os.cpus().length,model:os.cpus()[0].model,load:os.loadavg().map(x=>+x.toFixed(2)),mem:os.totalmem(),free:os.freemem(),up:os.uptime(),disk:d,hostname:os.hostname(),plat:os.platform()+' '+os.arch(),xray:!!xp,mtg:!!Object.keys(mp).length,hy:!!Object.keys(hp2).length}};
// ---------- SSL (Let's Encrypt با certbot) ----------
const LE=D+'/le',DOM=/^(?=.{4,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
const certbot=a=>new Promise(res=>{let o='';const p=spawn('certbot',[...a,'--config-dir',LE,'--work-dir',LE+'/w','--logs-dir',LE+'/l']);
  const t=setTimeout(()=>p.kill(),18e4);p.stdout.on('data',d=>o+=d);p.stderr.on('data',d=>o+=d);p.on('error',e=>{o+=e.message});p.on('close',c=>{clearTimeout(t);res({code:c,out:o.slice(-1500)})})});
const sslInfo=()=>{const s=db.settings.ssl;if(!s)return null;let v='';try{v=new cr.X509Certificate(fs.readFileSync(s.cert)).validTo}catch{}return{domain:s.domain,validTo:v,active:db.settings.cert==s.cert}};
const bad={};
app.post('/api/login',(q,r)=>{const ip=q.ip,b=bad[ip]||{n:0,t:0},now=Date.now();if(b.n>=5&&now-b.t<6e5)return r.sendStatus(429);
  if(db.settings.pass&&vp(q.body.p||'',db.settings.pass)){delete bad[ip];cookie(r);r.json({ok:1})}
  else{b.n=(now-b.t>6e5?0:b.n)+1;b.t=now;bad[ip]=b;setTimeout(()=>r.sendStatus(401),800)}});
app.use('/api',(q,r,n)=>ok(q)?n():r.sendStatus(401));
app.get('/api/state',(q,r)=>{const{pass,secret,...s}=db.settings;r.json({...db,settings:s,host:s.domain||q.hostname,sys:sysInfo(),ssl:sslInfo()})});
app.post('/api/settings',(q,r)=>{const b=q.body,s=db.settings;
  ['panelPort','subPort'].forEach(k=>b[k]&&(s[k]=+b[k]));['domain','cert','key'].forEach(k=>k in b&&(s[k]=b[k]));
  if(b.newpass&&b.newpass.length>=6)s.pass=hp(b.newpass);apply();r.json({ok:1});setTimeout(listen,300)});
app.post('/api/ssl/issue',async(q,r)=>{const d=(q.body.domain||'').trim().toLowerCase(),e=(q.body.email||'').trim();
  if(!DOM.test(d)||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))return r.json({ok:false,out:'دامنه یا ایمیل نامعتبر است'});
  const x=await certbot(['certonly','--standalone','--preferred-challenges','http','-d',d,'-m',e,'--agree-tos','--non-interactive','--cert-name',d]);
  if(x.code==0){db.settings.ssl={domain:d,cert:`${LE}/live/${d}/fullchain.pem`,key:`${LE}/live/${d}/privkey.pem`};logA('دریافت SSL: '+d);save()}
  r.json({ok:x.code==0,out:x.out})});
app.post('/api/ssl/apply',(q,r)=>{const s=db.settings,l=s.ssl;if(!l||!fs.existsSync(l.cert))return r.json({ok:false});
  s.cert=l.cert;s.key=l.key;s.domain=l.domain;apply();r.json({ok:true,url:`https://${l.domain}:${s.panelPort}`});setTimeout(listen,300)});
app.post('/api/ssl/off',(q,r)=>{db.settings.cert='';db.settings.key='';apply();r.json({ok:true});setTimeout(listen,300)});
['inbounds','clients','nodes','mtproto'].forEach(k=>{
  app.post('/api/'+k,(q,r)=>{const b=q.body;let o=db[k].find(x=>x.id==b.id);if(!o){o={id:uid(),on:true};db[k].push(o)}
    if(k=='clients'){o.uuid=o.uuid||uid();o.token=o.token||hex(12);b.inb=b.inb||[];if(!o.wgPub){const k=wk();o.wgPriv=k.priv;o.wgPub=k.pub;o.wgN=Math.max(1,...db.clients.map(x=>x.wgN||1))+1}if(+b.days)b.exp=Date.now()+b.days*864e5;delete b.days}
    if(k=='mtproto'&&!o.secret)o.secret='ee'+hex(16)+Buffer.from(b.domain||'www.google.com').toString('hex');
    if(k=='nodes'&&!o.key)o.key=hex(16);
    const id=o.id;Object.assign(o,b,{id});if(o.port)o.port=+o.port;
    if(k=='inbounds'&&o.sec=='reality'&&!o.priv)gen(o);
    if(k=='inbounds'&&o.protocol=='wireguard'&&!o.wgPriv){const w=wk();o.wgPriv=w.priv;o.wgPub=w.pub}
    logA('ثبت/ویرایش '+k+': '+(o.remark||o.email||o.name||''));
    apply();r.json(o)});
  app.post('/api/'+k+'/:id/toggle',(q,r)=>{const o=db[k].find(x=>x.id==q.params.id);if(o)o.on=o.on===false;apply();r.json({ok:1})});
  app.delete('/api/'+k+'/:id',(q,r)=>{db[k]=db[k].filter(x=>x.id!=q.params.id);logA('حذف '+k);apply();r.json({ok:1})});
});

// ---------- ساب و صفحه کاربر (پورت جدا) ----------
const QR=t=>{const g=qrg(0,'M');g.addData(t);g.make();return g.createSvgTag({cellSize:4,margin:0,scalable:true})};
const sub=express();
sub.get('/sub/:t',(q,r)=>{const c=db.clients.find(x=>x.token==q.params.t);if(!c)return r.sendStatus(404);
  r.set('subscription-userinfo',`upload=0; download=${c.used||0}; total=${(+c.limit||0)*2**30}; expire=${Math.floor((c.exp||0)/1e3)}`);
  r.send(b64(links(c).join('\n')))});
sub.get('/u/:t',(q,r)=>{const c=db.clients.find(x=>x.token==q.params.t);if(!c)return r.sendStatus(404);
  const tot=+c.limit||0,u=(c.used||0)/2**30,pc=tot?Math.min(100,u/tot*100).toFixed(0):0,
  d=c.exp?Math.max(0,Math.ceil((c.exp-Date.now())/864e5)):'∞',su=`${q.protocol}://${q.headers.host}/sub/${c.token}`;
  const data=JSON.stringify({L:links(c),su}).replace(/</g,'\\u003c');
  r.send(`<!doctype html><html lang=fa dir=rtl><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AHB</title>
<style>*{box-sizing:border-box;font-family:Tahoma,sans-serif}body{margin:0;padding:16px;background:#050a1e;color:#e8eeff;max-width:560px;margin:auto}
.c{background:#0a1330;border:1px solid #1b3a8a66;border-radius:16px;padding:16px;margin-bottom:12px}
.ring{width:130px;height:130px;border-radius:50%;background:conic-gradient(#00e5a0 ${pc}%,#1b2550 0);display:grid;place-items:center;margin:auto}
.ring i{width:100px;height:100px;border-radius:50%;background:#0a1330;display:grid;place-items:center;font-style:normal;font-size:24px}
.g{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;text-align:center}.g b{display:block;font-size:20px;margin-top:6px}
button{width:100%;padding:12px;border:0;border-radius:10px;color:#fff;background:linear-gradient(90deg,#1d6bff,#6a4dff);margin-top:8px;font-size:15px}
code{display:block;direction:ltr;word-break:break-all;font-size:12px;background:#060c24;padding:8px;border-radius:8px;margin-top:8px}</style>
<div class=c><b>${c.on===false?'⛔ غیرفعال':'✅ اشتراک فعال'}</b> — ${c.email}<br><br><div class=ring><i>${pc}%</i></div></div>
<div class="c g"><div>مصرف<b>${u.toFixed(1)} GB</b></div><div>باقیمانده<b>${tot?(tot-u).toFixed(1)+' GB':'∞'}</b></div><div>روز<b>${d}</b></div></div>
<div class=c><b>لینک اشتراک</b><code id=su></code><button onclick="navigator.clipboard.writeText(D.su)">کپی لینک</button><div style="background:#fff;padding:10px;width:200px;margin:12px auto 0">${QR(su)}</div></div>
<div class=c><b>کانفیگ‌ها</b><div id=ls></div></div>
<script>const D=${data};su.textContent=D.su;D.L.forEach(l=>{const e=document.createElement('code');e.textContent=l;e.onclick=()=>navigator.clipboard.writeText(l);ls.appendChild(e)});
</script>`)});

// ---------- اجرا ----------
let srv=[];
function listen(){srv.forEach(s=>{s.close();s.closeAllConnections&&s.closeAllConnections()});const s=db.settings;
  const mk=(a,p)=>{const o=s.cert&&s.key&&fs.existsSync(s.cert)&&fs.existsSync(s.key)?https.createServer({cert:fs.readFileSync(s.cert),key:fs.readFileSync(s.key)},a):http.createServer(a);
    o.on('error',e=>console.log('listen error',p,e.message));o.listen(p,'0.0.0.0');return o};
  setTimeout(()=>{srv=[mk(app,process.env.PORT||s.panelPort),mk(sub,s.subPort)]},300)}
setInterval(async()=>{
  let hb=0;const add=j=>{for(const s of(j.stat||[])){const m=s.name.split('>>>');if(m[0]!='user')continue;const c=db.clients.find(x=>x.email==m[1]);if(c){c.used=(c.used||0)+ +(s.value||0);hb+= +(s.value||0)}}};
  add(qs());
  for(const i of db.inbounds.filter(i=>i.protocol=='hysteria2'&&i.sp&&hp2[i.id])){try{const j=await(await fetch(`http://127.0.0.1:${i.sp}/traffic?clear=1`)).json();for(const e in j)add({stat:[{name:`user>>>${e}>>>traffic>>>x`,value:(j[e].tx||0)+(j[e].rx||0)}]})}catch{}}
  for(const n of db.nodes){try{const r=await fetch(`http://${n.address}:${n.port||62050}/stats`,{headers:{'x-key':n.key}});if(!r.ok)throw 0;add(await r.json());if(!n.ok)push(n);n.ok=1}catch{n.ok=0}}
  const hh=Math.floor(Date.now()/36e5)*36e5;let he=db.hist.find(x=>x.t==hh);if(!he){he={t:hh,b:0};db.hist.push(he);db.hist=db.hist.slice(-168)}he.b+=hb;
  let ch=0;const now=Date.now();
  db.clients.forEach(c=>{if(c.on!==false&&((+c.limit&&(c.used||0)>=c.limit*2**30)||(c.exp&&c.exp<now))){c.on=false;ch=1}});
  ch?apply():save()},30000);
setInterval(async()=>{if(!db.settings.ssl)return;const b=sslInfo().validTo;await certbot(['renew','--non-interactive','--quiet']);if(sslInfo().validTo!=b){if(db.settings.cert)listen();apply()}},864e5);
listen();apply();
console.log('AHB Panel 14.4.0 — panel:',db.settings.panelPort,'sub:',db.settings.subPort);
