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
let db={settings:{panelPort:2053,subPort:2096,domain:'',cert:'',key:'',pass:'',secret:hex(32)},inbounds:[],resellers:[],clients:[],nodes:[],mtproto:[],hist:[],log:[],groups:[]};
if(fs.existsSync(F))db=Object.assign(db,JSON.parse(fs.readFileSync(F)));
const save=()=>fs.writeFileSync(F,JSON.stringify(db,null,1));

// ---------- ساخت کانفیگ Xray ----------
const first=s=>String(s||'').split(',')[0].trim(),lst=s=>String(s||'').split(',').map(x=>x.trim()).filter(Boolean),SSM='chacha20-ietf-poly1305',TLP=['vless','vmess','trojan','shadowsocks'];
const xin=i=>{
  const cl=db.clients.filter(c=>c.on!==false&&(c.inb||[]).includes(i.id)),P=i.protocol,n=i.net||'tcp',sec=i.sec||'none',m=i.ssm||SSM;let s={};
  if(P=='vless')s={clients:cl.map(c=>{const o={id:c.uuid,email:c.email};if(i.flow&&n=='tcp'&&sec!='none')o.flow=i.flow;return o}),decryption:'none'};
  else if(P=='vmess')s={clients:cl.map(c=>({id:c.uuid,email:c.email}))};
  else if(P=='trojan')s={clients:cl.map(c=>({password:c.uuid,email:c.email}))};
  else if(P=='shadowsocks')s={method:m,network:'tcp,udp',clients:cl.map(c=>({password:c.uuid,email:c.email,method:m}))};
  else if(P=='socks'||P=='http')s={auth:'password',udp:true,accounts:cl.map(c=>({user:c.email,pass:c.uuid}))};
  else if(P=='wireguard')s={secretKey:i.wgPriv,mtu:1420,peers:cl.map(c=>({publicKey:c.wgPub,allowedIPs:[`10.66.0.${c.wgN}/32`]}))};
  else if(P=='dokodemo-door')s={address:i.target||'127.0.0.1',port:+i.tport||80,network:'tcp,udp'};
  const o={tag:'in-'+i.id,port:+i.port,listen:i.listen||'0.0.0.0',protocol:P,settings:s,sniffing:i.sniff=='0'?{enabled:false}:{enabled:true,destOverride:['http','tls','quic']}};
  if(TLP.includes(P)){
    const st={network:n,security:sec},p=i.path||'/',h=i.host||undefined;
    if(n=='ws')st.wsSettings={path:p,headers:h?{Host:h}:undefined};if(n=='grpc')st.grpcSettings={serviceName:i.path||'grpc'};
    if(n=='httpupgrade')st.httpupgradeSettings={path:p,host:h};if(n=='xhttp')st.xhttpSettings={path:p,host:h,mode:i.mode||'auto'};
    if(sec=='tls')st.tlsSettings={serverName:first(i.sni)||undefined,alpn:lst(i.alpn).length?lst(i.alpn):undefined,certificates:[{certificateFile:i.cert||db.settings.cert,keyFile:i.key||db.settings.key}]};
    if(sec=='reality'){const nm=lst(i.sni).length?lst(i.sni):['www.microsoft.com'],sid=lst(i.sid);
      st.realitySettings={show:false,dest:i.dest||nm[0]+':443',xver:0,serverNames:nm,privateKey:i.priv,shortIds:sid.length?sid:['']}}
    o.streamSettings=st;
  }
  return o;
};
const build=nid=>({log:{loglevel:'warning'},stats:{},api:{tag:'api',services:['StatsService']},
  policy:{levels:{0:{statsUserUplink:true,statsUserDownlink:true}}},
  inbounds:[{tag:'api',listen:'127.0.0.1',port:10085,protocol:'dokodemo-door',settings:{address:'127.0.0.1'}},
    ...db.inbounds.filter(i=>i.on!==false&&(i.node||'local')==nid&&!['hysteria2','mtproto'].includes(i.protocol)).map(xin)],
  outbounds:[{protocol:'freedom',tag:'direct'},{protocol:'blackhole',tag:'block'}],
  routing:{rules:[{type:'field',inboundTag:['api'],outboundTag:'api'}]}});
const b64u=b=>b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),PK8=Buffer.from('302e020100300506032b656e04220420','hex');
const x25=()=>{const k=cr.generateKeyPairSync('x25519');return{priv:b64u(k.privateKey.export({type:'pkcs8',format:'der'}).slice(-32)),pub:b64u(k.publicKey.export({type:'spki',format:'der'}).slice(-32))}};
const pubOf=p=>{try{const r=Buffer.from(String(p).trim().replace(/-/g,'+').replace(/_/g,'/'),'base64');if(r.length!=32)return'';
  return b64u(cr.createPublicKey(cr.createPrivateKey({key:Buffer.concat([PK8,r]),format:'der',type:'pkcs8'})).export({type:'spki',format:'der'}).slice(-32))}catch{return''}};
const gen=i=>{const k=x25();i.priv=k.priv;i.pub=k.pub};

// ---------- نودها و پروکسی تلگرام ----------
const push=n=>fetch(`http://${n.address}:${n.port||62050}/config`,{method:'POST',headers:{'x-key':n.key,'content-type':'application/json'},body:JSON.stringify(build(n.id))}).then(()=>n.ok=1).catch(()=>n.ok=0);
const mp={};
const mt=()=>{for(const k in mp){mp[k].kill();delete mp[k]}
  db.mtproto.filter(m=>m.on!==false).forEach(m=>{mp[m.id]=spawn('mtg',['simple-run','0.0.0.0:'+m.port,m.secret],{stdio:'inherit'})});
  db.inbounds.filter(i=>i.protocol=='mtproto'&&i.on!==false&&i.secret&&(i.node||'local')=='local').forEach(i=>{mp['i'+i.id]=spawn('mtg',['simple-run','0.0.0.0:'+i.port,i.secret],{stdio:'inherit'})})};
const wk=()=>{const k=cr.generateKeyPairSync('x25519');return{priv:k.privateKey.export({type:'pkcs8',format:'der'}).slice(-32).toString('base64'),pub:k.publicKey.export({type:'spki',format:'der'}).slice(-32).toString('base64')}};
const logA=t=>{db.log.unshift({t:Date.now(),m:t});db.log=db.log.slice(0,200)};
const tgSend=t=>{const g=db.settings.tg;if(g&&g.token&&g.chat)fetch(`https://api.telegram.org/bot${g.token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:g.chat,text:t})}).catch(()=>0)};
const hp2={};
const hy=()=>{for(const k in hp2){hp2[k].kill();delete hp2[k]}
  db.inbounds.filter(i=>i.protocol=='hysteria2'&&i.on!==false&&(i.node||'local')=='local').forEach((i,n)=>{
    i.sp=40000+n;const cl=db.clients.filter(c=>c.on!==false&&(c.inb||[]).includes(i.id)),f=`${D}/hy-${i.id}.yaml`;
    fs.writeFileSync(f,`listen: :${i.port}\ntls:\n  cert: ${i.cert||db.settings.cert}\n  key: ${i.key||db.settings.key}\nauth:\n  type: userpass\n  userpass:\n${cl.map(c=>`    "${c.email}": "${c.uuid}"`).join('\n')||'    x: x'}\ntrafficStats:\n  listen: 127.0.0.1:${i.sp}\n`);
    hp2[i.id]=spawn('hysteria',['server','-c',f],{stdio:'inherit'})})};
const apply=()=>{save();fs.writeFileSync(X,JSON.stringify(build('local')));runX();db.nodes.forEach(push);mt();hy()};

// ---------- لینک‌ها و فرمت‌های ساب (base64 / raw / clash / sing-box) ----------
const fh=h=>h.includes(':')&&!h.startsWith('[')?`[${h}]`:h;
const cxs=(c,dh)=>db.inbounds.filter(i=>i.on!==false&&(c.inb||[]).includes(i.id)).map(i=>{
  const nd=db.nodes.find(n=>n.id==i.node),P=i.protocol,tl=TLP.includes(P),net=tl?(i.net||'tcp'):'tcp',sec=tl?(i.sec||'none'):'none';
  return{P,c,h:i.addr||(nd&&nd.address)||db.settings.domain||dh||'SERVER_IP',port:+i.port,nm:i.remark+'-'+c.email,id:c.uuid,net,sec,
    sni:sec=='reality'?(first(i.sni)||'www.microsoft.com'):first(i.sni),path:net=='grpc'?(i.path||'grpc'):(i.path||'/'),host:i.host||'',mode:i.mode||'auto',
    flow:P=='vless'&&net=='tcp'&&sec!='none'?(i.flow||''):'',fp:sec!='none'?(i.fp||'chrome'):'',alpn:lst(i.alpn),insecure:!!i.insecure,
    secret:i.secret||'',pbk:i.pub||'',sid:first(i.sid),spx:i.spx||'',ssm:i.ssm||SSM,wgPub:i.wgPub}}).map((x,k,a)=>{const d=a.slice(0,k).filter(y=>y.nm==x.nm||y.nm.startsWith(x.nm+'#')).length;return d?{...x,nm:x.nm+'#'+(d+1)}:x});
const lk=x=>{const q=new URLSearchParams(),e=encodeURIComponent(x.nm),h=fh(x.h);
  switch(x.P){
    case'vless':case'trojan':{q.set('type',x.net);if(x.P=='vless')q.set('encryption','none');q.set('security',x.sec);
      if(x.net=='tcp')q.set('headerType','none');
      if(['ws','httpupgrade','xhttp'].includes(x.net)){q.set('path',x.path);if(x.host)q.set('host',x.host);if(x.net=='xhttp')q.set('mode',x.mode)}
      if(x.net=='grpc'){q.set('serviceName',x.path);q.set('mode','gun')}
      if(x.sec!='none'){if(x.sni)q.set('sni',x.sni);if(x.fp)q.set('fp',x.fp);if(x.alpn.length)q.set('alpn',x.alpn.join(','))}
      if(x.sec=='tls'&&x.insecure)q.set('allowInsecure','1');
      if(x.sec=='reality'){q.set('pbk',x.pbk);q.set('sid',x.sid);if(x.spx)q.set('spx',x.spx)}
      if(x.flow)q.set('flow',x.flow);
      return`${x.P}://${x.id}@${h}:${x.port}?${q}#${e}`}
    case'vmess':return'vmess://'+b64(JSON.stringify({v:2,ps:x.nm,add:x.h,port:x.port,id:x.id,aid:0,scy:'auto',net:x.net=='tcp'?'tcp':x.net,type:x.net=='grpc'?'gun':'none',host:x.host,path:x.net=='tcp'?'':x.path,tls:x.sec=='tls'?'tls':'',sni:x.sni,alpn:x.alpn.join(','),fp:x.fp}));
    case'shadowsocks':return x.net=='tcp'&&x.sec=='none'?`ss://${b64(x.ssm+':'+x.id)}@${h}:${x.port}#${e}`:'';
    case'wireguard':return`wireguard://${encodeURIComponent(x.c.wgPriv)}@${h}:${x.port}?address=10.66.0.${x.c.wgN}/32&publickey=${encodeURIComponent(x.wgPub)}&mtu=1420#${e}`;
    case'hysteria2':return`hysteria2://${encodeURIComponent(x.c.email)}:${x.id}@${h}:${x.port}/?sni=${x.sni||x.h}${x.insecure?'&insecure=1':''}#${e}`;
    case'socks':return`socks://${b64(x.c.email+':'+x.id)}@${h}:${x.port}#${e}`;
  }return'';};
const tgLinks=(c,dh)=>cxs(c,dh).filter(x=>x.P=='mtproto'&&x.secret).map(x=>({n:x.nm,u:`tg://proxy?server=${x.h}&port=${x.port}&secret=${x.secret}`,w:`https://t.me/proxy?server=${x.h}&port=${x.port}&secret=${x.secret}`}));
const links=(c,dh)=>cxs(c,dh).map(lk).filter(Boolean);
const clTr=(x,o)=>{
  if(x.net=='ws'||x.net=='httpupgrade'){o.network='ws';o['ws-opts']={path:x.path,headers:x.host?{Host:x.host}:undefined,'v2ray-http-upgrade':x.net=='httpupgrade'||undefined}}
  else if(x.net=='grpc'){o.network='grpc';o['grpc-opts']={'grpc-service-name':x.path}}else o.network='tcp';
  if(x.sec!='none'){o.tls=true;o[x.P=='trojan'?'sni':'servername']=x.sni||undefined;o['client-fingerprint']=x.fp||undefined;if(x.alpn.length)o.alpn=x.alpn;if(x.insecure)o['skip-cert-verify']=true;
    if(x.sec=='reality')o['reality-opts']={'public-key':x.pbk,'short-id':x.sid}}};
const cl=x=>{if(x.net=='xhttp')return null;const o={name:x.nm,server:x.h,port:x.port,udp:true};
  switch(x.P){
    case'vless':Object.assign(o,{type:'vless',uuid:x.id,'packet-encoding':'xudp',flow:x.flow||undefined});clTr(x,o);return o;
    case'vmess':Object.assign(o,{type:'vmess',uuid:x.id,alterId:0,cipher:'auto'});clTr(x,o);return o;
    case'trojan':Object.assign(o,{type:'trojan',password:x.id});clTr(x,o);return o;
    case'shadowsocks':return x.net=='tcp'&&x.sec=='none'?Object.assign(o,{type:'ss',cipher:x.ssm,password:x.id}):null;
    case'hysteria2':return Object.assign(o,{type:'hysteria2',password:x.c.email+':'+x.id,sni:x.sni||x.h,'skip-cert-verify':x.insecure||undefined});
    case'wireguard':return Object.assign(o,{type:'wireguard',ip:'10.66.0.'+x.c.wgN,'private-key':x.c.wgPriv,'public-key':x.wgPub,mtu:1420});
    case'socks':return Object.assign(o,{type:'socks5',username:x.c.email,password:x.id});
    case'http':return Object.assign(o,{type:'http',username:x.c.email,password:x.id});
  }return null};
const sbTr=(x,o)=>{
  if(x.net=='ws')o.transport={type:'ws',path:x.path,headers:x.host?{Host:x.host}:undefined};
  else if(x.net=='httpupgrade')o.transport={type:'httpupgrade',path:x.path,host:x.host||undefined};
  else if(x.net=='grpc')o.transport={type:'grpc',service_name:x.path};
  if(x.sec!='none'){o.tls={enabled:true,server_name:x.sni||undefined,insecure:x.insecure||undefined,alpn:x.alpn.length?x.alpn:undefined,utls:{enabled:true,fingerprint:x.fp||'chrome'}};
    if(x.sec=='reality')o.tls.reality={enabled:true,public_key:x.pbk,short_id:x.sid}}};
const sb=x=>{if(x.net=='xhttp')return null;const o={tag:x.nm,server:x.h,server_port:x.port};
  switch(x.P){
    case'vless':Object.assign(o,{type:'vless',uuid:x.id,flow:x.flow||undefined,packet_encoding:'xudp'});sbTr(x,o);return o;
    case'vmess':Object.assign(o,{type:'vmess',uuid:x.id,security:'auto',alter_id:0});sbTr(x,o);return o;
    case'trojan':Object.assign(o,{type:'trojan',password:x.id});sbTr(x,o);return o;
    case'shadowsocks':return x.net=='tcp'&&x.sec=='none'?Object.assign(o,{type:'shadowsocks',method:x.ssm,password:x.id}):null;
    case'hysteria2':return Object.assign(o,{type:'hysteria2',password:x.c.email+':'+x.id,tls:{enabled:true,server_name:x.sni||x.h,insecure:x.insecure||undefined}});
    case'socks':return Object.assign(o,{type:'socks',version:'5',username:x.c.email,password:x.id});
    case'http':return Object.assign(o,{type:'http',username:x.c.email,password:x.id});
  }return null};
const FMT={
  b64:xs=>[b64(xs.map(lk).filter(Boolean).join('\n')),'text/plain'],
  raw:xs=>[xs.map(lk).filter(Boolean).join('\n'),'text/plain'],
  clash:xs=>{const ps=xs.map(cl).filter(Boolean),nm=ps.map(p=>p.name),y=o=>'  - '+JSON.stringify(o);
    return[['mixed-port: 7890','allow-lan: false','mode: rule','log-level: warning','ipv6: false','proxies:'+(ps.length?'':' []'),...ps.map(y),'proxy-groups:',
      y({name:'AHB',type:'select',proxies:nm.length?['auto',...nm,'DIRECT']:['DIRECT']}),
      ...(nm.length?[y({name:'auto',type:'url-test',proxies:nm,url:'https://www.gstatic.com/generate_204',interval:300,tolerance:50})]:[]),
      'rules:','  - MATCH,AHB'].join('\n'),'text/yaml']},
  singbox:xs=>{const ob=xs.map(sb).filter(Boolean),t=ob.map(o=>o.tag);
    return[JSON.stringify({log:{level:'warn'},
      inbounds:[{type:'tun',tag:'tun-in',address:['172.19.0.1/30','fdfe:dcba:9876::1/126'],auto_route:true,strict_route:true,stack:'mixed'},{type:'mixed',tag:'mixed-in',listen:'127.0.0.1',listen_port:2080}],
      outbounds:[{type:'selector',tag:'proxy',outbounds:t.length?['auto',...t,'direct']:['direct']},...(t.length?[{type:'urltest',tag:'auto',outbounds:t,url:'https://www.gstatic.com/generate_204',interval:'5m'}]:[]),...ob,{type:'direct',tag:'direct'}],
      route:{auto_detect_interface:true,final:'proxy',rules:[{action:'sniff'},{protocol:'dns',action:'hijack-dns'}]}},null,1),'application/json']}};
const FA={b64:'b64',base64:'b64',v2ray:'b64',raw:'raw',txt:'raw',clash:'clash',mihomo:'clash',meta:'clash',stash:'clash',singbox:'singbox','sing-box':'singbox',sb:'singbox'};
const fmtOf=q=>{const f=FA[String(q.params.f||q.query.format||'').toLowerCase()];if(f)return f;const ua=(q.headers['user-agent']||'').toLowerCase();
  if(/sing-?box|sagernet|^sf[aimt]\b|\bsf[aimt]\//.test(ua))return'singbox';
  if(/clash|mihomo|stash|flclash|verge|clashx|koala/.test(ua))return'clash';return'b64'};

// ---------- احراز هویت ----------
const sign=t=>cr.createHmac('sha256',db.settings.secret).update(t).digest('hex');
const cookie=r=>{const e=Date.now()+6048e5;r.setHeader('Set-Cookie',`ahb=${e}.${sign(''+e)};HttpOnly;Path=/;SameSite=Strict;Max-Age=604800`)};
const ok=r=>{const m=/ahb=([^;]+)/.exec(r.headers.cookie||'');if(!m)return false;const[e,s]=m[1].split('.');return +e>Date.now()&&s==sign(e)};
const hp=p=>{const s=hex(8);return s+':'+cr.scryptSync(p,s,32).toString('hex')};
const vp=(p,h)=>{const[s,x]=h.split(':'),y=cr.scryptSync(p,s,32).toString('hex');return x==y};

const app=express();app.use(express.json({limit:'10mb'}));const IDX=[__dirname+'/public/index.html',__dirname+'/index.html'].find(f=>fs.existsSync(f));
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
app.get('/api/state',(q,r)=>{const{pass,secret,...s}=db.settings;s.tg=s.tg?{chat:s.tg.chat,on:!!s.tg.token}:null;r.json({...db,resellers:db.resellers.map(({ph,...x})=>x),settings:s,host:s.domain||q.hostname,sys:sysInfo(),ssl:sslInfo()})});
app.post('/api/settings',(q,r)=>{const b=q.body,s=db.settings;
  ['panelPort','subPort'].forEach(k=>b[k]&&(s[k]=+b[k]));['domain','cert','key','support','subTitle','subInterval'].forEach(k=>k in b&&(s[k]=b[k]));
  if(b.newpass&&b.newpass.length>=6)s.pass=hp(b.newpass);apply();r.json({ok:1});setTimeout(listen,300)});
app.post('/api/xray/keys',(q,r)=>r.json({...x25(),sid:hex(4)}));
app.get('/api/backup',(q,r)=>{r.setHeader('Content-Disposition','attachment; filename=ahb-backup.json');r.type('json').send(JSON.stringify(db))});
app.post('/api/restore',(q,r)=>{if(!q.body||!q.body.settings)return r.sendStatus(400);db=q.body;db.groups=db.groups||[];db.resellers=db.resellers||[];db.log=db.log||[];db.hist=db.hist||[];apply();r.json({ok:1})});
app.post('/api/logoutall',(q,r)=>{db.settings.secret=hex(32);save();cookie(r);r.json({ok:1})});
app.post('/api/bot',(q,r)=>{const g=db.settings.tg=db.settings.tg||{};if(q.body.token)g.token=q.body.token.trim();g.chat=(q.body.chat||'').trim();save();r.json({ok:1})});
app.post('/api/bot/test',(q,r)=>{tgSend('✅ ربات AHB Panel متصل است');r.json({ok:1})});
app.post('/api/ssl/issue',async(q,r)=>{const d=(q.body.domain||'').trim().toLowerCase(),e=(q.body.email||'').trim();
  if(!DOM.test(d)||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))return r.json({ok:false,out:'دامنه یا ایمیل نامعتبر است'});
  const x=await certbot(['certonly','--standalone','--preferred-challenges','http','-d',d,'-m',e,'--agree-tos','--non-interactive','--cert-name',d]);
  if(x.code==0){db.settings.ssl={domain:d,cert:`${LE}/live/${d}/fullchain.pem`,key:`${LE}/live/${d}/privkey.pem`};logA('دریافت SSL: '+d);save()}
  r.json({ok:x.code==0,out:x.out})});
app.post('/api/ssl/apply',(q,r)=>{const s=db.settings,l=s.ssl;if(!l||!fs.existsSync(l.cert))return r.json({ok:false});
  s.cert=l.cert;s.key=l.key;s.domain=l.domain;apply();r.json({ok:true,url:`https://${l.domain}:${s.panelPort}`});setTimeout(listen,300)});
app.post('/api/ssl/off',(q,r)=>{db.settings.cert='';db.settings.key='';apply();r.json({ok:true});setTimeout(listen,300)});
['inbounds','clients','nodes','mtproto','groups','resellers'].forEach(k=>{
  app.post('/api/'+k,(q,r)=>{const b=q.body;let o=db[k].find(x=>x.id==b.id);if(!o){o={id:uid(),on:true};db[k].push(o)}
    if(k=='clients'&&b.group){const g=db.groups.find(x=>x.id==b.group);if(g){if(!+b.limit)b.limit=g.limit;if(!+b.days&&!o.exp)b.days=g.days;if(!(b.inb||[]).length)b.inb=g.inb||[]}}
    if(k=='clients'){o.uuid=o.uuid||uid();o.token=o.token||hex(12);b.inb=b.inb||[];if(!o.wgPub){const k=wk();o.wgPriv=k.priv;o.wgPub=k.pub;o.wgN=Math.max(1,...db.clients.map(x=>x.wgN||1))+1}if(+b.days)b.exp=Date.now()+b.days*864e5;delete b.days}
    if(k=='mtproto'&&!o.secret)o.secret='ee'+hex(16)+Buffer.from(b.domain||'www.google.com').toString('hex');
    if(k=='nodes'&&!o.key)o.key=hex(16);
    if(k=='resellers'){if(b.user&&db.resellers.some(x=>x.user==b.user&&x.id!=o.id)){if(!o.user)db.resellers=db.resellers.filter(x=>x!==o);return r.status(400).json({error:'dup'})}
      if(b.pass)o.ph=hp(b.pass);delete b.pass;if(+b.days)b.exp=Date.now()+b.days*864e5;delete b.days;b.gb=+b.gb||0;b.maxc=+b.maxc||0;b.groups=b.groups||[];b.inb=b.inb||[]}
    if(k=='clients'||k=='groups'){b.limit=Math.max(0,+b.limit||0);if(k=='groups')b.days=Math.max(0,+b.days||0)}
    const id=o.id;Object.assign(o,b,{id});if(o.port)o.port=+o.port;
    if(k=='inbounds'&&o.sec=='reality'){if(!o.priv)gen(o);else{const p=pubOf(o.priv);if(p)o.pub=p}
      o.sid=lst(o.sid).filter(x=>/^([0-9a-f]{2}){1,8}$/i.test(x)).join(',')||hex(4)}
    if(k=='inbounds'&&o.protocol=='mtproto'){o.mk=o.mk||hex(16);o.secret='ee'+o.mk+Buffer.from(first(o.sni)||'www.google.com').toString('hex')}
    if(k=='inbounds'&&o.protocol=='wireguard'&&!o.wgPriv){const w=wk();o.wgPriv=w.priv;o.wgPub=w.pub}
    logA('ثبت/ویرایش '+k+': '+(o.remark||o.email||o.name||''));
    apply();r.json(o)});
  app.post('/api/'+k+'/:id/toggle',(q,r)=>{const o=db[k].find(x=>x.id==q.params.id);if(o)o.on=o.on===false;apply();r.json({ok:1})});
  app.delete('/api/'+k+'/:id',(q,r)=>{db[k]=db[k].filter(x=>x.id!=q.params.id);logA('حذف '+k);apply();r.json({ok:1})});
});


// ---------- پنل نمایندگی ----------
const rsign=(i,e)=>sign('r'+i+'.'+e),rcookie=(r,i)=>{const e=Date.now()+864e5*3;r.setHeader('Set-Cookie',`ahr=${i}.${e}.${rsign(i,e)};HttpOnly;Path=/;SameSite=Strict;Max-Age=259200`)};
const rget=q=>{const m=/ahr=([^;]+)/.exec(q.headers.cookie||'');if(!m)return null;const[i,e,s]=m[1].split('.');if(!(+e>Date.now())||s!=rsign(i,e))return null;
  const x=db.resellers.find(z=>z.id==i);return x&&x.on!==false&&!(x.exp&&x.exp<Date.now())?x:null};
const rmine=x=>db.clients.filter(c=>c.owner==x.id),GB=2**30;
const ralloc=x=>rmine(x).reduce((a,c)=>a+(+c.limit||0),0)+(x.burn||0);
const rinfo=x=>({name:x.name,gb:x.gb||0,alloc:+ralloc(x).toFixed(2),exp:x.exp||0,maxc:x.maxc||0});
const initC=o=>{o.uuid=o.uuid||uid();o.token=o.token||hex(12);if(!o.wgPub){const k=wk();o.wgPriv=k.priv;o.wgPub=k.pub;o.wgN=Math.max(1,...db.clients.map(x=>x.wgN||1))+1}};
app.get('/reseller',(q,r)=>r.sendFile(__dirname+'/public/reseller.html'));
app.post('/rapi/login',(q,r)=>{const ip='r'+q.ip,b=bad[ip]||{n:0,t:0},now=Date.now();if(b.n>=5&&now-b.t<6e5)return r.sendStatus(429);
  const x=db.resellers.find(z=>z.user==q.body.u&&z.ph);
  if(x&&x.on!==false&&vp(q.body.p||'',x.ph)){delete bad[ip];rcookie(r,x.id);r.json({ok:1})}
  else{b.n=(now-b.t>6e5?0:b.n)+1;b.t=now;bad[ip]=b;setTimeout(()=>r.sendStatus(401),800)}});
app.use('/rapi',(q,r,n)=>{q.rs=rget(q);q.rs?n():r.sendStatus(401)});
app.get('/rapi/state',(q,r)=>{const x=q.rs,h=db.settings.domain||q.hostname;
  r.json({me:rinfo(x),host:h,subPort:db.settings.subPort,proto:q.protocol,
    groups:db.groups.filter(g=>(x.groups||[]).includes(g.id)).map(g=>({id:g.id,name:g.name,limit:g.limit,days:g.days,inb:(g.inb||[]).filter(i=>(x.inb||[]).includes(i))})),
    inbounds:db.inbounds.filter(i=>(x.inb||[]).includes(i.id)).map(i=>({id:i.id,remark:i.remark,protocol:i.protocol,port:i.port})),
    clients:rmine(x).map(c=>({id:c.id,email:c.email,group:c.group,limit:c.limit,used:c.used||0,exp:c.exp||0,on:c.on!==false,token:c.token,inb:c.inb||[]}))})});
app.post('/rapi/clients',(q,r)=>{const x=q.rs,b=q.body||{},er=m=>r.status(400).json({error:m});
  let o=b.id?rmine(x).find(c=>c.id==b.id):null;if(b.id&&!o)return er('کاربر پیدا نشد');
  const email=String(b.email||(o&&o.email)||'').trim();if(!/^[\w.\-@]{2,40}$/.test(email))return er('نام کاربر نامعتبر است (حروف انگلیسی/عدد، ۲ تا ۴۰ کاراکتر)');
  if(db.clients.some(c=>c.email==email&&c!==o))return er('این نام قبلاً استفاده شده');
  const g=db.groups.find(z=>z.id==b.group&&(x.groups||[]).includes(z.id));if(b.group&&!g)return er('گروه مجاز نیست');
  let inb=(Array.isArray(b.inb)?b.inb:[]).filter(i=>(x.inb||[]).includes(i));if(!inb.length&&g)inb=(g.inb||[]).filter(i=>(x.inb||[]).includes(i));
  if(!inb.length)return er('حداقل یک اینباند مجاز انتخاب کن');
  const lim=+b.limit||(g&&+g.limit)||0;if(!(lim>0))return er('حجم باید بیشتر از صفر باشد');
  const al=ralloc(x)-(o?+o.limit||0:0)+lim;if(x.gb&&al>x.gb+1e-9)return er(`سهمیه کافی نیست (باقی‌مانده ${(x.gb-ralloc(x)+(o?+o.limit||0:0)).toFixed(3)} GB)`);
  if(!o&&x.maxc&&rmine(x).length>=x.maxc)return er('به سقف تعداد کاربر رسیده‌اید');
  let days=+b.days||(g&&+g.days)||0;if(!o&&!(days>0))return er('مدت (روز) را مشخص کن');
  if(days>0&&x.exp&&Date.now()+days*864e5>x.exp+864e5)return er('مدت کاربر از اعتبار باقی‌مانده نماینده بیشتر است');
  if(!o){o={id:uid(),on:true,owner:x.id};db.clients.push(o)}initC(o);
  Object.assign(o,{email,group:g?g.id:'',limit:lim,inb});if(days>0)o.exp=Date.now()+days*864e5;
  logA(`نماینده ${x.name}: ثبت/ویرایش ${email}`);apply();r.json({ok:1,token:o.token})});
app.post('/rapi/clients/:id/toggle',(q,r)=>{const o=rmine(q.rs).find(c=>c.id==q.params.id);if(!o)return r.sendStatus(404);
  if(o.on===false&&((+o.limit&&(o.used||0)>=o.limit*GB)||(o.exp&&o.exp<Date.now())))return r.status(400).json({error:'حجم یا زمان کاربر تمام شده؛ ابتدا ویرایش و تمدید کن'});
  o.on=o.on===false;apply();r.json({ok:1})});
app.delete('/rapi/clients/:id',(q,r)=>{const x=q.rs,o=rmine(x).find(c=>c.id==q.params.id);if(!o)return r.sendStatus(404);
  x.burn=(x.burn||0)+(o.used||0)/GB;db.clients=db.clients.filter(c=>c!==o);logA(`نماینده ${x.name}: حذف ${o.email}`);apply();r.json({ok:1})});
app.post('/rapi/logout',(q,r)=>{r.setHeader('Set-Cookie','ahr=;Path=/;Max-Age=0');r.json({ok:1})});

// ---------- ساب و صفحه کاربر (پورت جدا) ----------
const QR=t=>{const g=qrg(0,'M');g.addData(t);g.make();return g.createSvgTag({cellSize:4,margin:0,scalable:true})};
const sub=express();
sub.get('/sub/:t/:f?',(q,r)=>{const c=db.clients.find(x=>x.token==q.params.t);if(!c)return r.sendStatus(404);
  const s=db.settings,tot=(+c.limit||0)*2**30,ui=['upload=0','download='+(c.used||0)];if(tot)ui.push('total='+tot);if(c.exp)ui.push('expire='+Math.floor(c.exp/1e3));
  const[body,ty]=FMT[fmtOf(q)](cxs(c,q.hostname)),t=s.subTitle||'AHB';
  r.set({'subscription-userinfo':ui.join('; '),'profile-title':'base64:'+b64(t),'profile-update-interval':String(+s.subInterval||12),'profile-web-page-url':`${q.protocol}://${q.headers.host}/u/${c.token}`,
    'content-disposition':`attachment; filename*=UTF-8''${encodeURIComponent(t)}`,'cache-control':'no-store'});
  if(s.support)r.set('support-url',s.support);
  r.type(ty+'; charset=utf-8').send(body)});
const fb=b=>{b=+b||0;if(b<1024)return b+' B';const u=['KB','MB','GB','TB'];let i=-1;do{b/=1024;i++}while(b>=1024&&i<3);return(b>=100?b.toFixed(0):b>=10?b.toFixed(1):b.toFixed(2))+' '+u[i]};
const fd=t=>{if(t<=0)return'0 دقیقه';const d=Math.floor(t/864e5),h=Math.floor(t%864e5/36e5),m=Math.floor(t%36e5/6e4);return d?d+' روز'+(h?' و '+h+' ساعت':''):h?h+' ساعت'+(m?' و '+m+' دقیقه':''):Math.max(1,m)+' دقیقه'};
const fl=g=>{g=+g||0;return g?+g.toFixed(4)+' GB':'∞'};
sub.get('/u/:t',(q,r)=>{const c=db.clients.find(x=>x.token==q.params.t);if(!c)return r.sendStatus(404);
  const tot=+c.limit||0,u=(c.used||0)/2**30,pc=tot?(u>0&&u/tot*100<1?(u/tot*100).toFixed(2):Math.min(100,u/tot*100).toFixed(0)):0,d=c.exp?fd(c.exp-Date.now()):'نامحدود',su=`${q.protocol}://${q.headers.host}/sub/${c.token}`;
  const gi=db.groups.find(g=>g.id==c.group),ib=db.inbounds.find(i=>(c.inb||[]).includes(i.id))||{},on=c.on!==false,dm=db.settings.domain||q.hostname;
  const sv=[{n:'سرور اصلی',f:'🏠',ok:1},...db.nodes.map(n=>({n:n.name,f:n.flag||'🌐',ok:n.ok}))];
  const e=x=>String(x).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
  const data=JSON.stringify({T:tgLinks(c,q.hostname),L:links(c,q.hostname),su,pw:c.uuid}).replace(/</g,'\\u003c');
  r.send(`<!doctype html><html lang=fa dir=rtl><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AHB</title>
<style>*{box-sizing:border-box;font-family:Tahoma,sans-serif}body{margin:auto;background:radial-gradient(circle at 70% 0,#1a1060,#050a1e 55%) fixed;color:#e8eeff;max-width:620px;padding:14px 14px 90px}
.c{background:#0a1330;border:1px solid #1f3f9a66;border-radius:16px;padding:16px;margin-bottom:12px}.hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.logo{font:900 28px sans-serif;background:linear-gradient(90deg,#1d6bff,#6a4dff);-webkit-background-clip:text;color:transparent}
.plan{display:flex;justify-content:space-between;align-items:center;background:linear-gradient(120deg,#0b2a8a,#3a1070)}
.bd{background:#0a2a1f;color:#00e5a0;border-radius:8px;padding:5px 12px;font-size:13px;display:inline-block}.bd.x{background:#3a0a14;color:#ff4d6d}.vip{background:#3a2a0a;color:#ffc34d;border-radius:8px;padding:3px 10px;font-size:13px}
.ring{width:120px;height:120px;border-radius:50%;background:conic-gradient(#00e5a0 ${pc}%,#1b2550 0);display:grid;place-items:center;flex:none}.ring i{width:92px;height:92px;border-radius:50%;background:#0b1236;display:grid;place-items:center;font-style:normal;font-size:20px;text-align:center}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}.g4 div{background:#0a1330;border:1px solid #1f3f9a66;border-radius:14px;padding:12px 4px;text-align:center;font-size:12px;color:#8fa3d6}.g4 b{display:block;color:#fff;font-size:16px;margin:6px 0}
.row{display:flex;justify-content:space-between;background:#0d1a40;border-radius:10px;padding:11px 12px;margin:6px 0;font-size:14px}.row span:last-child{direction:ltr}
button{width:100%;padding:12px;border:0;border-radius:12px;color:#fff;background:linear-gradient(90deg,#1d6bff,#6a4dff);margin-top:8px;font-size:15px}.b2{background:linear-gradient(90deg,#6a4dff,#a64dff)}
.sv{display:grid;grid-template-columns:1fr 1fr;gap:8px}.sv div{background:#0d1a40;border-radius:12px;padding:10px;display:flex;justify-content:space-between;font-size:14px}
select{width:100%;padding:10px;background:#060c24;border:1px solid #1f3f9a66;border-radius:10px;color:#fff;font-size:13px}code{display:block;direction:ltr;word-break:break-all;font-size:12px;background:#060c24;padding:8px;border-radius:8px;margin-top:6px}
.bn{position:fixed;bottom:0;left:0;right:0;background:#060d26;border-top:1px solid #1f3f9a66;display:flex;justify-content:space-around;padding:10px 0;font-size:12px}.bn a{color:#8fa3d6;text-decoration:none;text-align:center}
@media(max-width:420px){.g4{grid-template-columns:1fr 1fr}}</style>
<div class=hd><span class=logo>AHB</span><span style="color:#8fa3d6;font-size:13px">اتصال سریع، بدون محدودیت</span></div>
<div class="c plan"><div><span class="bd ${on?'':'x'}">${on?'✔ اشتراک فعال':'⛔ غیرفعال'}</span><h2 style="margin:12px 0 4px">${e(gi?gi.name:'طرح ویژه')}</h2>
<div style="color:#8fa3d6;font-size:13px">تاریخ انقضا: ${c.exp?new Date(c.exp).toLocaleDateString('fa-IR'):'نامحدود'}</div><div style="margin-top:10px"><span class=vip>👑 VIP</span> <small style="color:#8fa3d6">دسترسی کامل به تمام سرورها</small></div></div>
<div class=ring><i>${pc}%<br><small style="font-size:12px">مصرف شده</small></i></div></div>
<div class=g4><div>حجم مصرفی<b>${fb(c.used||0)}</b>${tot?'از '+fl(tot):''}</div><div>حجم باقیمانده<b>${tot?fb(Math.max(0,tot*2**30-(c.used||0))):'∞'}</b></div><div>زمان باقی‌مانده<b>${d}</b></div><div>سرعت اتصال<b>نامحدود</b>بدون محدودیت</div></div>
<div class=c><b>📡 اطلاعات اتصال</b>
<div class=row><span>نام کاربری</span><span>${e(c.email)}</span></div>
<div class=row><span>رمز عبور</span><span id=pw onclick="pw.textContent=pw.textContent=='••••••••'?D.pw:'••••••••'">••••••••</span></div>
<div class=row><span>آدرس سرور</span><span>${e(dm)}</span></div><div class=row><span>پورت</span><span>${ib.port||'-'}</span></div><div class=row><span>پروتکل</span><span>${(ib.protocol||'-').toUpperCase()}</span></div>
<div id=qr style="background:#fff;padding:10px;width:190px;margin:14px auto 0">${QR(su)}</div><button onclick="dq()">⬇ دانلود QR Code</button></div>
<div class=c><b>🔗 لینک اشتراک</b><select id=ap onchange="sl.textContent=D.su+ap.value"><option value="">عمومی — v2rayNG, v2rayN, Hiddify, NekoBox, Streisand, Shadowrocket, V2Box, Karing, Happ</option><option value="/clash">Clash / Mihomo — Clash Verge, FlClash, Stash, ClashX, Clash Meta</option><option value="/singbox">sing-box — SFA, SFI, SFM</option><option value="/raw">متن ساده (بدون base64)</option></select><code id=sl></code><button onclick="cp(D.su+ap.value)">کپی لینک</button><button class=b2 onclick="dl('config.txt',D.L.join(String.fromCharCode(10)),'text/plain')">⬇ دانلود فایل قابل کانفیگ</button></div>
${tgLinks(c,q.hostname).length?`<div class=c><b>✈️ پروکسی تلگرام</b><div id=tgp></div></div>`:''}
<div class=c><b>🖥 سرورهای فعال</b><div class=sv style="margin-top:8px">${sv.map(x=>`<div><span>${x.f} ${e(x.n)}</span><span style="color:${x.ok?'#00e5a0':'#ff4d6d'}">● ${x.ok?'فعال':'قطع'}</span></div>`).join('')}</div></div>
<div class=bn><a href="#">🏠<br>خانه</a><a href="#">ℹ️<br>اطلاعات</a><a href="#">⚙️<br>تنظیمات</a><a href="${db.settings.support||'#'}">🎧<br>پشتیبانی</a></div>
<script>const D=${data};sl.textContent=D.su;if(window.tgp)tgp.innerHTML=D.T.map(t=>'<code>'+t.n+'</code><a href="'+t.u+'"><button>اتصال در تلگرام</button></a><button class=b2 onclick="cp(\''+t.w+'\')">کپی لینک</button>').join('');
const cp=t=>navigator.clipboard.writeText(t).then(()=>alert('کپی شد'));
const dl=(n,t,m)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:m}));a.download=n;a.click()};
function dq(){let s=document.querySelector('#qr svg').outerHTML;if(!s.includes('xmlns'))s=s.replace('<svg','<svg xmlns="http://www.w3.org/2000/svg"');dl('qr.svg',s,'image/svg+xml')}</script>`)});

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
  for(const n of db.nodes){try{const r=await fetch(`http://${n.address}:${n.port||62050}/stats`,{headers:{'x-key':n.key}});if(!r.ok)throw 0;add(await r.json());if(!n.ok)push(n);n.ok=1}catch{if(n.ok)tgSend('🔴 نود '+n.name+' قطع شد');n.ok=0}}
  const hh=Math.floor(Date.now()/36e5)*36e5;let he=db.hist.find(x=>x.t==hh);if(!he){he={t:hh,b:0};db.hist.push(he);db.hist=db.hist.slice(-168)}he.b+=hb;
  let ch=0;const now=Date.now();
  db.clients.forEach(c=>{if(c.on!==false&&((+c.limit&&(c.used||0)>=c.limit*2**30)||(c.exp&&c.exp<now))){c.on=false;ch=1;tgSend('⛔ '+c.email+' غیرفعال شد')}});
  ch?apply():save()},30000);
let off=0;
(async function bot(){const t=db.settings.tg;let w=5000;
  if(t&&t.token){try{const j=await(await fetch(`https://api.telegram.org/bot${t.token}/getUpdates?timeout=20&offset=${off}`)).json();w=0;
    for(const u of j.result||[]){off=u.update_id+1;const m=u.message;if(!m||String(m.chat.id)!=String(t.chat))continue;const tx=m.text||'';
      if(tx.startsWith('/status'))tgSend(`👥 ${db.clients.length} کاربر (${db.clients.filter(c=>c.on!==false).length} فعال)\n📊 ${fb(db.clients.reduce((a,c)=>a+(c.used||0),0))}\n🖥 CPU ${cpuP}%`);
      if(tx.startsWith('/user ')){const c=db.clients.find(x=>x.email==tx.slice(6).trim());tgSend(c?`${c.email}: ${fb(c.used||0)} / ${c.limit?fl(c.limit):'∞'}`:'پیدا نشد')}}}catch{w=5000}}
  setTimeout(bot,w)})();
setInterval(async()=>{if(!db.settings.ssl)return;const b=sslInfo().validTo;await certbot(['renew','--non-interactive','--quiet']);if(sslInfo().validTo!=b){if(db.settings.cert)listen();apply()}},864e5);
listen();apply();
console.log('AHB Panel 14.6.0 — panel:',db.settings.panelPort,'sub:',db.settings.subPort);
