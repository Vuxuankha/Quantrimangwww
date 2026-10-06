'use strict';
/* 5.9.2 unified information architecture + small UX polish. Functional page renderers remain unchanged. */
tr.dashboard='Trung tâm điều hành';
tr.devices='Tài sản / IP-MAC';
tr.managed='Thiết bị quản trị';
tr.topology='Bản đồ mạng';
tr.alerts='Cảnh báo';
tr.incidents='Sự cố / RCA';
tr.reports='Báo cáo';
tr.accounts='Người dùng & Phân quyền';
tr.security='Bảo mật hệ thống';
tr.credentials='Credential & Trust';

const enterpriseGroups592=[
  ['TỔNG QUAN',['dashboard','daily57','soc51','taskcenter47']],
  ['THIẾT BỊ & MẠNG',['devices','managed','ipmac','profiles','organization','topology','lan','scan','netspeed59','pingmonitor','history','monitoringx','health','server','snmp','extensions','remote']],
  ['BẢO MẬT',['endpoint58','vuln51','siem51','threat54','cases55','security','alerts','rules','incidents','services','sla','inbox47']],
  ['VẬN HÀNH',['autoip','audit','terminal','backup','compare','dailyaudit','scheduler','restore','readiness','jobs','compliance53','notify56','reports']],
  ['QUẢN TRỊ',['accounts','credentials','vault51','crypto51','secpost51','production','runtime47','system46','platform50','auditall','parity','notify','logs','diag','settingsx','password']]
];
groups.splice(0,groups.length,...enterpriseGroups592);
state.groupOpen={0:true,1:true,2:true,3:false,4:false};

const enterpriseIcon={dashboard:'▦',daily57:'✓',soc51:'⬢',taskcenter47:'◴',devices:'▣',managed:'▤',ipmac:'#',profiles:'◇',organization:'▥',topology:'⌘',lan:'⌁',scan:'⌕',netspeed59:'⇅',pingmonitor:'⌁',history:'∿',monitoringx:'≋',health:'♥',server:'▰',snmp:'◎',extensions:'◉',remote:'↗',endpoint58:'▣',vuln51:'◈',siem51:'⚠',threat54:'◎',cases55:'▤',security:'⬟',alerts:'!',rules:'≡',incidents:'◆',services:'◫',sla:'◷',inbox47:'✦',autoip:'↻',audit:'>_',terminal:'>_',backup:'▰',compare:'≠',dailyaudit:'✓',scheduler:'◷',restore:'↶',readiness:'✓',jobs:'◴',compliance53:'✓',notify56:'✉',reports:'▥',accounts:'♙',credentials:'◇',vault51:'▣',crypto51:'◆',secpost51:'⬟',production:'◉',runtime47:'◌',system46:'✓',platform50:'◉',auditall:'✓',parity:'⇄',notify:'✉',logs:'≡',diag:'◇',settingsx:'⚙',password:'⌁'};
Object.assign(navIcon,enterpriseIcon);

const originalNavigation592=navigation;
navigation=function(){originalNavigation592();const nav=document.getElementById('navigation');if(!nav)return;nav.querySelectorAll('.nav-group-toggle').forEach((b,i)=>{b.title='Nhóm '+(enterpriseGroups592[i]?.[0]||'chức năng')});};

const titleMap592={dashboard:['Trung tâm điều hành an ninh','Giám sát mạng, bảo mật và hạ tầng IT theo thời gian thực'],daily57:['Việc cần làm hôm nay','Ưu tiên các mục cần xử lý trong ngày'],soc51:['SOC Dashboard','Tổng quan tình trạng an ninh và cảnh báo ưu tiên'],ipmac:['Tài sản / IP-MAC','Quản lý tài sản và địa chỉ đang quan sát trong mạng'],netspeed59:['Tốc độ & Đường truyền','Đo chất lượng kết nối, độ trễ, jitter và mất gói'],endpoint58:['Endpoint Monitoring','Theo dõi endpoint Windows/Linux và trạng thái bảo vệ'],vuln51:['Vulnerability Center','Quản lý phát hiện lỗ hổng và rủi ro'],siem51:['SIEM / Alerts','Sự kiện an ninh, tương quan và vòng đời cảnh báo'],threat54:['Threat Intel & Detection','IOC watchlist và luật phát hiện tùy chỉnh'],cases55:['Cases & Asset Risk','Điều tra sự cố, SLA và rủi ro tài sản']};
const oldGo592=go;
go=async function(page){await oldGo592(page);const map=titleMap592[page];if(map){const title=document.getElementById('title'),sub=document.getElementById('subtitle');if(title)title.textContent=map[0];if(sub)sub.textContent=map[1];}document.body.dataset.page=page;};

actions['autoops68-toggle']=async b=>{const enabled=b.dataset.enabled==='1';const action=enabled?'disable':'enable';const msg=enabled?'Tắt chế độ tự động toàn hệ thống?':'Bật chế độ tự động? Web sẽ tự chạy Presence, Live Discovery, Alert Rules, Incident/RCA, Server Monitor, Line Quality và backup DB theo chu kỳ.';if(!confirm(msg))return;await api('/v68/automation/'+action,{method:'POST'});toast(enabled?'Đã tắt tự động toàn hệ thống.':'Đã bật tự động toàn hệ thống.');await e592reloadAutoOps()};
actions['autoops68-run']=async()=>{if(!confirm('Chạy ngay tất cả tác vụ tự động an toàn?'))return;await api('/v68/automation/run-now',{method:'POST'});toast('Đã đưa tất cả tác vụ tự động vào chạy.');setTimeout(()=>void e592reloadAutoOps(),700)};
if(!window.__e592AutoOpsTimer){window.__e592AutoOpsTimer=setInterval(()=>{if(state.page==='dashboard')void e592reloadAutoOps()},15000)}

const initEnterprise592=()=>{
  const quick=document.querySelector('.header-right button[data-action="quick-find47"]');
  if(quick){quick.textContent='Tìm thiết bị, IP, cảnh báo, chức năng...';quick.setAttribute('aria-label','Tìm nhanh toàn hệ thống');}
  const brand=document.querySelector('.brand small');if(brand)brand.textContent='Cybersecurity Platform / UI 6.9.0';
  const notice=document.querySelector('main>.notice');if(notice)notice.textContent='NetworkAutomation Cybersecurity UI 6.9.0 · Core API 5.9.2 · Dữ liệu trạng thái chỉ được coi là hiện tại khi có phép đo mới.';
};
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initEnterprise592,{once:true});else initEnterprise592();
window.naEnterprise592={version:'6.6.0',groups:enterpriseGroups592.map(x=>x[0])};

/* 5.9.2 UI hotfix R2: real dashboard redesign. This final override intentionally replaces
   the legacy operations dashboard rather than only restyling its existing markup. */
function e592safe(p,fallback){return api(p).catch(()=>fallback)}
function e592sevClass(v){const s=String(v||'').toLowerCase();return ['critical','high','medium','low'].includes(s)?s:'info'}
function e592num(v){const n=Number(v||0);return Number.isFinite(n)?n:0}
function e592riskBar(score){const n=Math.max(0,Math.min(100,e592num(score)));return `<div class="e592-riskbar"><span style="width:${n}%"></span></div>`}
function e592metric(icon,label,value,meta,tone='blue'){return `<div class="e592-metric ${tone}"><div class="e592-metric-icon">${icon}</div><div><small>${esc(label)}</small><strong>${esc(value)}</strong><span>${esc(meta||'')}</span></div></div>`}
function e592alertRows(rows){if(!rows?.length)return '<div class="e592-empty">Không có cảnh báo an ninh gần đây.</div>';return rows.slice(0,6).map(x=>`<button class="e592-alert-row" data-action="page" data-page="siem51"><span class="e592-alert-dot ${e592sevClass(x.severity)}"></span><span class="e592-alert-main"><b>${esc(x.title||x.message||'Security alert')}</b><small>${esc(x.asset_ip||x.subject_user||'—')} · ${esc(x.last_seen||x.created_at||'')}</small></span><span class="badge ${e592sevClass(x.severity)}">${esc(x.severity||'INFO')}</span></button>`).join('')}
function e592dailyCards(d){const rows=(d?.tasks||[]).filter(x=>x.needs_attention).slice(0,6);if(!rows.length)return `<div class="e592-clear"><b>✓ Không có mục ưu tiên</b><span>Checklist hiện tại không ghi nhận việc cần xử lý.</span></div>`;return rows.map(x=>`<button class="e592-daily-card ${e592sevClass(x.severity)}" data-action="page" data-page="${esc(x.page||'daily57')}"><span class="e592-daily-count">${esc(x.count||0)}</span><span><b>${esc(x.title)}</b><small>${esc(x.detail||'Mở để kiểm tra')}</small></span><i>›</i></button>`).join('')}
function e592endpointSummary(rows){const total=rows?.length||0;const risky=(rows||[]).filter(x=>['HIGH','CRITICAL'].includes(String(x.risk_level||'').toUpperCase())).length;const stale=(rows||[]).filter(x=>{const t=Date.parse(x.last_seen||'');return !Number.isFinite(t)||Date.now()-t>300000}).length;return {total,risky,stale,ok:Math.max(0,total-Math.max(risky,stale))}}


function e592ago(v){const t=Date.parse(v||'');if(!Number.isFinite(t))return 'chưa có';const s=Math.max(0,Math.round((Date.now()-t)/1000));if(s<60)return s+' giây trước';if(s<3600)return Math.floor(s/60)+' phút trước';if(s<86400)return Math.floor(s/3600)+' giờ trước';return Math.floor(s/86400)+' ngày trước'}
function e592presenceRows(rows){
  const data=(rows||[]).slice().sort((a,b)=>String(a.status||'').localeCompare(String(b.status||''))||String(a.ip||'').localeCompare(String(b.ip||'')));
  const offline=data.filter(x=>String(x.status||'').toLowerCase()==='offline');
  const unknown=data.filter(x=>String(x.status||'').toLowerCase()==='unknown');
  if(!offline.length&&!unknown.length)return '<div class="e592-presence-ok"><b>✓ Tất cả thiết bị đang hoạt động</b><span>Chưa ghi nhận máy mất kết nối.</span></div>';
  const rowsHtml=offline.slice(0,12).map(x=>`<div class="e592-presence-row"><span class="e592-presence-dot offline"></span><span><b>${esc(x.hostname||x.name||x.ip||'Thiết bị')}</b><small>${esc(x.ip||x.ip_address||'—')} · ${esc(x.mac||x.mac_address||'Không có MAC')} · thấy lần cuối ${esc(e592ago(x.last_seen_at||x.last_seen))}</small></span><em>Mất kết nối / tắt máy</em></div>`).join('');
  const unknownHtml=unknown.slice(0,6).map(x=>`<div class="e592-presence-row"><span class="e592-presence-dot"></span><span><b>${esc(x.hostname||x.name||x.ip||'Thiết bị')}</b><small>${esc(x.ip||x.ip_address||'—')} · mất phản hồi ${esc(x.consecutive_misses||1)} lần</small></span><em>Đang xác minh</em></div>`).join('');
  const more=Math.max(0,offline.length-12)+Math.max(0,unknown.length-6);
  return `<div class="e592-presence-list">${rowsHtml}${unknownHtml}${more?`<div class="e592-presence-more">+ ${more} thiết bị khác</div>`:''}</div>`;
}
function e592presenceEvents(events){const rows=(events||[]).filter(x=>x.old_status&&x.old_status!==x.new_status).slice(0,8);if(!rows.length)return '<div class="e592-empty">Chưa có thay đổi trạng thái được ghi nhận.</div>';return rows.map(x=>`<div class="e592-presence-event"><span class="e592-presence-dot ${String(x.new_status).toLowerCase()==='offline'?'offline':''}"></span><span><b>${esc(x.hostname||x.ip)}</b><small>${esc(x.ip)} · ${esc(x.old_status)} → ${esc(x.new_status)}</small></span><em>${esc(e592ago(x.observed_at))}</em></div>`).join('')}
function e592updatePresence(rows){
  const total=(rows||[]).length, online=(rows||[]).filter(x=>String(x.status||'').toLowerCase()==='online').length, offline=(rows||[]).filter(x=>String(x.status||'').toLowerCase()==='offline').length;
  const a=document.getElementById('e592-presence-online'),b=document.getElementById('e592-presence-offline'),c=document.getElementById('e592-presence-total'),list=document.getElementById('e592-presence-list');
  if(a)a.textContent=online;if(b)b.textContent=offline;if(c)c.textContent=total;if(list)list.innerHTML=e592presenceRows(rows);
}
async function e592refreshPresence(){
  if(state.page!=='dashboard')return;
  const btn=document.getElementById('e592-presence-refresh');if(btn){btn.disabled=true;btn.textContent='Đang kiểm tra...'}
  try{const r=await api('/devices/refresh-status',{method:'POST'});if(state.page==='dashboard')e592updatePresence(r.results||[])}catch(e){console.warn('presence refresh',e)}finally{if(btn){btn.disabled=false;btn.textContent='Kiểm tra lại'}}
}

function e592autoOpsCard(a){
  a=a||{};const enabled=!!a.enabled,tasks=a.tasks||[],running=Number(a.running_count||0);
  const pass=tasks.filter(x=>String(x.last_status||'').toUpperCase()==='PASS').length;
  const fail=tasks.filter(x=>String(x.last_status||'').toUpperCase()==='FAIL').length;
  const taskRows=tasks.map(x=>`<div class="e592-auto-task"><span class="e592-auto-dot ${x.running?'running':String(x.last_status||'').toLowerCase()}"></span><span><b>${esc(x.label||x.task_key)}</b><small>${x.running?'Đang chạy':x.last_finished_at?('Lần cuối '+esc(e592ago(x.last_finished_at))):'Chưa chạy'} · chu kỳ ${Math.max(1,Math.round(Number(x.interval_seconds||60)/60))} phút</small></span><em>${esc(x.running?'RUNNING':x.last_status||'WAITING')}</em></div>`).join('');
  const controls=isAdmin()?`<div class="e592-auto-controls"><button type="button" class="${enabled?'danger':'primary'}" data-action="autoops68-toggle" data-enabled="${enabled?'1':'0'}">${enabled?'Tắt tự động toàn hệ thống':'Bật tự động toàn hệ thống'}</button><button type="button" data-action="autoops68-run">Chạy tất cả ngay</button></div>`:'';
  return `<section class="e592-autoops ${enabled?'enabled':''}"><div class="e592-auto-head"><div><span class="eyebrow">MASTER AUTOMATION 6.8</span><h3>Tự động vận hành toàn hệ thống</h3><p>Bật một lần để Web tự chạy các tác vụ giám sát và bảo trì an toàn theo chu kỳ.</p></div><div class="e592-auto-state"><span class="e592-auto-lamp ${enabled?'on':'off'}"></span><strong>${enabled?'ĐANG BẬT':'ĐANG TẮT'}</strong><small>${running} tác vụ đang chạy · ${pass} PASS · ${fail} FAIL</small></div>${controls}</div><details ${enabled?'open':''}><summary>${tasks.length} tác vụ tự động</summary><div class="e592-auto-grid">${taskRows||'<div class="e592-empty">Chưa có trạng thái tác vụ.</div>'}</div><p class="e592-auto-note">An toàn: không tự xóa/restore, đổi credential, Auto IP, config restore, vulnerability scan, speed test WAN hoặc ghi cấu hình từ xa.</p></details></section>`;
}
async function e592reloadAutoOps(){if(state.page!=='dashboard')return;try{const a=await api('/v68/automation');const box=document.getElementById('e592-autoops-host');if(box)box.innerHTML=e592autoOpsCard(a)}catch(e){console.warn('autoops status',e)}}
if(!window.__e592PresenceTimer){window.__e592PresenceTimer=setInterval(()=>{if(state.page==='dashboard')void e592refreshPresence()},30000)}

pages.dashboard=async()=>{
  const [ops,sec,daily,net,endpoints,risk,cases,devRows,presence,history,idguard,autoops]=await Promise.all([
    e592safe('/dashboard',{}),e592safe('/v51/dashboard',{}),e592safe('/v57/daily',{}),
    e592safe('/v59/network/summary',{}),e592safe('/v58/endpoints',[]),e592safe('/v55/risk/assets?limit=8',[]),e592safe('/v55/summary',{}),e592safe('/devices',[]),
    e592safe('/devices/presence-state',{results:[],online:0,offline:0,unknown:0}),e592safe('/devices/presence-history?limit=40',{events:[]}),e592safe('/devices/identity-conflicts',{count:0,conflicts:[]}),e592safe('/v68/automation',{enabled:false,tasks:[],running_count:0})
  ]);
  const ep=e592endpointSummary(endpoints);const line=net.latest_line||{};const identity=net.identity||{};
  const critical=e592num(sec.critical_alerts),high=e592num(sec.high_alerts),medium=(sec.alerts||[]).filter(x=>String(x.severity).toUpperCase()==='MEDIUM').length;
  const score=e592num(sec.security_score);const devices=e592num(ops.devices);const presenceRows=(presence.results||[]).length?(presence.results||[]):devRows;const presenceTotal=(presence.results||[]).length?e592num(presence.count):presenceRows.length;const online=(presence.results||[]).length?e592num(presence.online):e592num(ops.online);const offline=(presence.results||[]).length?e592num(presence.offline):e592num(ops.offline);const unknown=(presence.results||[]).length?e592num(presence.unknown):Math.max(0,presenceTotal-online-offline);const onlinePct=presenceTotal?Math.round(online/presenceTotal*100):0;
  const riskRows=(risk||[]).slice(0,5).map(x=>`<tr><td><b>${esc(x.asset_ip)}</b></td><td><span class="badge ${e592sevClass(x.risk_level)}">${esc(x.risk_score)}</span>${e592riskBar(x.risk_score)}</td><td>${esc(x.open_alerts)}</td><td>${esc(x.vulnerability_findings)}</td></tr>`).join('')||'<tr><td colspan="4">Chưa có dữ liệu rủi ro tài sản.</td></tr>';
  const quality=String(line.grade||'CHƯA ĐO').toUpperCase();const qclass=quality==='POOR'?'bad':quality==='FAIR'?'warn':'good';
  const dailyCount=e592num(daily.attention_items);const alertTotal=e592num(sec.open_alerts);
  return `<div class="e592-dashboard">
    <section class="e592-topline"><div><span class="eyebrow">CYBERSECURITY OPERATIONS PLATFORM</span><h2>Trung tâm điều hành an ninh</h2><p>Giám sát mạng, bảo mật và hạ tầng IT theo dữ liệu thực tế.</p></div><div class="e592-top-actions">${button('Việc cần làm hôm nay','page',{page:'daily57'},'primary')}${button('SOC Dashboard','page',{page:'soc51'})}${button('Tốc độ mạng','page',{page:'netspeed59'})}</div></section>
    <div id="e592-autoops-host">${e592autoOpsCard(autoops)}</div>
    <section class="e592-metrics">
      ${e592metric('▣','Tài sản đang quản lý',devices,`${presenceTotal} thiết bị trong Presence`,'blue')}
      ${e592metric('!','Cảnh báo nghiêm trọng',critical+high,`${critical} Critical · ${high} High`,'red')}
      ${e592metric('◉','Thiết bị online',online,`${onlinePct}% tổng thiết bị hiện diện`,'cyan')}
      ${e592metric('⬟','Security Score',score+'/100',`${e592num(sec.vulnerability_findings)} vulnerability findings`,'amber')}
    </section>
    <section class="e592-daily"><div class="e592-section-head"><div><span class="eyebrow">DAILY SECURITY</span><h3>Việc cần làm hôm nay</h3><p>${dailyCount} mục cần chú ý · ${daily.reviewed_today?'Đã kiểm tra hôm nay':'Chưa đánh dấu kiểm tra'}</p></div><div>${canAnalyze()?button(daily.reviewed_today?'Đã kiểm tra':'Đánh dấu đã kiểm tra','daily-reviewed57',{},daily.reviewed_today?'':'primary'):''}</div></div><div class="e592-daily-grid">${e592dailyCards(daily)}</div></section>
    <section class="e592-main-grid"><div class="e592-main-column">
      <div class="e592-panel e592-presence-panel"><div class="e592-section-head"><div><h3>Máy đang hoạt động trong mạng</h3><p>Tự kiểm tra định kỳ. Máy tắt hoặc rời mạng sẽ chuyển sang trạng thái mất kết nối.</p></div><button id="e592-presence-refresh" type="button" onclick="void e592refreshPresence()">Kiểm tra lại</button></div><div class="e592-presence-summary"><div class="online"><small>Đang hoạt động</small><strong id="e592-presence-online">${online}</strong></div><div class="offline"><small>Mất kết nối / tắt máy</small><strong id="e592-presence-offline">${offline}</strong></div><div><small>Tổng thiết bị</small><strong id="e592-presence-total">${presenceTotal}</strong></div></div><div class="e592-presence-meta"><span>${unknown} đang xác minh</span><span>${e592num(idguard.count)} xung đột định danh MAC/IP</span></div><div id="e592-presence-list">${e592presenceRows(presenceRows)}</div><div class="e592-presence-history"><h4>Thay đổi trạng thái gần đây</h4>${e592presenceEvents(history.events||[])}</div></div>
      <div class="e592-panel"><div class="e592-section-head"><div><h3>Top tài sản có rủi ro cao</h3><p>Risk Score từ cảnh báo và vulnerability findings.</p></div>${button('Asset Risk','page',{page:'cases55'})}</div><div class="scroll"><table class="e592-risk-table"><thead><tr><th>IP / Asset</th><th>Risk</th><th>Alerts</th><th>CVE</th></tr></thead><tbody>${riskRows}</tbody></table></div></div>
      <div class="e592-panel"><div class="e592-section-head"><div><h3>Cảnh báo mới nhất</h3><p>Ưu tiên Critical/High trước.</p></div>${button('Mở SIEM','page',{page:'siem51'})}</div><div class="e592-alert-list">${e592alertRows(sec.alerts||[])}</div></div>
    </div><aside class="e592-right-rail">
      <div class="e592-side-card"><div class="e592-side-title"><span>⌁</span><div><b>Tình trạng đường truyền</b><small>${esc(identity.mode||'OFFLINE')}</small></div><span class="e592-quality ${qclass}">${esc(quality)}</span></div><div class="e592-network-grid"><div><small>Latency</small><strong>${line.latency_ms==null?'—':esc(line.latency_ms)+' ms'}</strong></div><div><small>Jitter</small><strong>${line.jitter_ms==null?'—':esc(line.jitter_ms)+' ms'}</strong></div><div><small>Packet loss</small><strong>${line.packet_loss==null?'—':esc(line.packet_loss)+'%'}</strong></div><div><small>IP máy giám sát</small><strong>${esc(identity.local_ip||'—')}</strong></div></div>${button('Đo lại ngay','page',{page:'netspeed59'},'primary')}</div>
      <div class="e592-side-card"><div class="e592-section-head"><div><h3>Endpoint Monitoring</h3><p>${ep.total} endpoint</p></div>${button('Xem','page',{page:'endpoint58'})}</div><div class="e592-endpoint-donut" style="--ok:${ep.total?Math.round(ep.ok/ep.total*100):0}"><div><strong>${ep.total}</strong><small>Endpoint</small></div></div><div class="e592-legend"><span><i class="ok"></i>${ep.ok} OK</span><span><i class="bad"></i>${ep.risky} rủi ro cao</span><span><i class="stale"></i>${ep.stale} mất check-in</span></div></div>
      <div class="e592-side-card"><div class="e592-section-head"><div><h3>Vận hành SOC</h3><p>Case & xử lý</p></div>${button('Cases','page',{page:'cases55'})}</div><div class="e592-soc-mini"><div><small>Case đang mở</small><strong>${esc(cases.open_cases||0)}</strong></div><div><small>Critical case</small><strong>${esc(cases.critical_cases||0)}</strong></div><div><small>IOC matches</small><strong>${esc(cases.ioc_matches||0)}</strong></div><div><small>Failed login 24h</small><strong>${esc(sec.failed_logins_24h||0)}</strong></div></div></div>
    </aside></section>
  </div>`;
  setTimeout(()=>{if(state.page==='dashboard')void e592refreshPresence()},700);
};

const initEnterprise592R2=()=>{document.body.classList.add('enterprise-dashboard-r2');const n=document.querySelector('main>.notice');if(n)n.classList.add('e592-system-note');};
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initEnterprise592R2,{once:true});else initEnterprise592R2();
window.naEnterprise592.uiHotfix='R2';
