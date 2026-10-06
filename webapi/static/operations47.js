'use strict';
// Remain inert if an earlier extension failed to load; central boot names the missing file.
if (typeof livePages46 !== 'undefined' && typeof window.patchHTML46 === 'function' && window.terminal46) {
/* 4.7 operations: additive views, no implicit device operations, no automatic reload. */
const ops47 = {deviceId:0,selected:new Set(),faults:[],boot:null,healthBusy:false,offline:false,sessionAt:0,plan:null,navFilter:'',jobsFilter:'all',inboxFilter:'active'};
window.ops47 = ops47;
Object.assign(tr,{device47:'H\u1ed3 s\u01a1 thi\u1ebft b\u1ecb',inbox47:'H\u1ed9p c\u1ea3nh b\u00e1o Ping',runtime47:'S\u1ee9c kh\u1ecfe h\u1ec7 th\u1ed1ng',taskcenter47:'Trung t\u00e2m t\u00e1c v\u1ee5'});
groups[0][1].push('taskcenter47');groups[2][1].splice(1,0,'inbox47');groups[5][1].unshift('runtime47');
Object.assign(navIcon,{inbox47:'!',runtime47:'\u2661',taskcenter47:'\u25f7'});
for(const page of ['device47','inbox47','runtime47','taskcenter47'])if(location.hash.slice(1)===page)state.page=page;
for(const page of ['device47','inbox47','runtime47','taskcenter47'])livePages46.add(page);
const number47 = v => v == null || v === '' ? '\u2014' : Number.isFinite(Number(v)) ? Number(v).toFixed(2).replace(/\.?0+$/, '') || '0' : '\u2014';
const fmt47 = v => v == null ? '\u2014' : esc(String(v));
const bytes47 = n => n == null?'\u2014':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(1)+' GB';
const duration47 = s => {s=Math.max(0,Number(s)||0);return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m '+Math.floor(s%60)+'s';};
function note47(message,kind=''){return `<div class="notice47 ${kind}" role="status">${message}</div>`;}
function fault47(code,extra={}){ops47.faults.push({at:new Date().toISOString(),code,...extra});if(ops47.faults.length>60)ops47.faults.shift();}
window.addEventListener('error',e=>fault47('JAVASCRIPT_ERROR',{file:(e.filename||'').split('/').pop().split('?')[0],line:e.lineno||0}));
window.addEventListener('unhandledrejection',()=>fault47('UNHANDLED_PROMISE'));
function systemNote47(message,error=false){const n=$('#system-alert47');if(n){n.textContent=message;n.classList.toggle('hidden',!message);n.classList.toggle('error',error);}}
window.addEventListener('offline',()=>{ops47.offline=true;systemNote47('Tr\u00ecnh duy\u1ec7t m\u1ea5t k\u1ebft n\u1ed1i. Gi\u1eef nguy\u00ean trang; kh\u00f4ng t\u1ef1 g\u1eedi l\u1ea1i l\u1ec7nh.',true);});
window.addEventListener('online',()=>{ops47.offline=false;systemNote47('K\u1ebft n\u1ed1i tr\u1edf l\u1ea1i; \u0111ang ki\u1ec3m tra API. L\u1ec7nh c\u0169 kh\u00f4ng t\u1ef1 ch\u1ea1y l\u1ea1i.');void healthCheck();});

/* No writes retried. The same timeout covers body decoding, not only headers. */
api = async function(path,options={}) {
 const method=options.method||'GET',ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),20000);
 const headers={'Content-Type':'application/json',...(options.headers||{})};
 if(!['GET','HEAD'].includes(method)&&state.csrf)headers['X-CSRF-Token']=state.csrf;
 let r,d;
 try {
  r=await fetch('/api'+path,{...options,headers,credentials:'same-origin',signal:ctrl.signal});
  try{d=await r.json();}catch(e){if(e.name==='AbortError')throw e;throw new Error('API_RESPONSE_NOT_JSON ('+r.status+')');}
  if(!r.ok){
   const requestId=r.headers.get('X-Request-ID')||d.request_id||'';
   // Validation replies may contain input values: never stringify those values.
   const detail=typeof d.detail==='string'?d.detail:Array.isArray(d.detail)?d.detail.map(x=>(x.loc||[]).join('.')+': '+x.msg).join('; '):'API_ERROR';
   fault47('HTTP_'+r.status,{request_id:requestId,method});
   if(r.status===401&&path!=='/auth/login'&&path!=='/auth/mfa/verify')await naConfirmSessionAfter401(path);
   const err=new Error(detail+(requestId?' [ref '+requestId+']':''));err.httpStatus=r.status;throw err;
  }
  return d;
 }catch(e){
  if(e.name==='AbortError'){fault47('API_TIMEOUT',{method});throw new Error('H\u1ebft th\u1eddi gian ch\u1edd API. T\u00e1c v\u1ee5 c\u00f3 th\u1ec3 v\u1eabn ch\u1ea1y; xem Trung t\u00e2m t\u00e1c v\u1ee5 tr\u01b0\u1edbc khi b\u1ea5m l\u1ea1i.');}
  if(e instanceof TypeError){fault47('API_UNREACHABLE',{method});throw new Error('Ch\u01b0a k\u1ebft n\u1ed1i \u0111\u01b0\u1ee3c API. Gi\u1eef nguy\u00ean trang v\u00e0 ki\u1ec3m tra server; kh\u00f4ng t\u1ef1 g\u1eedi l\u1ea1i l\u1ec7nh.');}
  throw e;
 }finally{clearTimeout(timer);}
};
healthCheck=async function(){
 if(ops47.healthBusy)return;ops47.healthBusy=true;
 try{
  const r=await api('/health');$('#api-state').textContent='API '+r.version;$('#api-state').className='badge online';
  if(r.version!=='5.9.2-cybersecurity'||r.ui_version!=='6.9.0'){state.uiReady=false;systemNote47('Giao diện và API khác phiên bản. Hãy tải lại đúng bản UI 6.9.0 trước khi gửi tác vụ mới.',true);return;}
  if(ops47.boot&&r.boot_id!==ops47.boot)systemNote47('Server v\u1eeba kh\u1edfi \u0111\u1ed9ng l\u1ea1i. Ki\u1ec3m tra t\u00e1c v\u1ee5 b\u1ecb gi\u00e1n \u0111o\u1ea1n; terminal v\u00e0 l\u1ec7nh c\u0169 kh\u00f4ng t\u1ef1 ch\u1ea1y l\u1ea1i.',true);
  ops47.boot=r.boot_id;
  if(state.user&&Date.now()-ops47.sessionAt>60000){ops47.sessionAt=Date.now();const session=await api('/v47/session');if(session.absolute_remaining_seconds<600)systemNote47('Phi\u00ean \u0111\u0103ng nh\u1eadp c\u00f2n '+Math.ceil(session.absolute_remaining_seconds/60)+' ph\u00fat. L\u01b0u c\u00f4ng vi\u1ec7c v\u00e0 ng\u1eaft terminal an to\u00e0n.');}
 }catch(e){$('#api-state').textContent='API ch\u01b0a k\u1ebft n\u1ed1i';$('#api-state').className='badge offline';}
 finally{ops47.healthBusy=false;}
};

/* Navigation filtering and quick find never dispatch device commands. */
const baseNavigation47=navigation;
function filterNavigation47(){
 const q=ops47.navFilter.toLocaleLowerCase('vi');
 for(const section of document.querySelectorAll('#navigation .nav-section')){
  let found=0;for(const b of section.querySelectorAll('button.nav')){const permitted=!(b.dataset.page==='runtime47'&&!isAdmin())&&!(b.dataset.page==='taskcenter47'&&!canWrite());const yes=permitted&&(!q||b.textContent.toLocaleLowerCase('vi').includes(q));b.hidden=!yes;if(yes)found++;}
  section.hidden=found===0;if(q&&found)section.querySelector('.nav-items')?.classList.remove('hidden');
 }
}
navigation=function(){baseNavigation47();filterNavigation47();};
document.addEventListener('input',e=>{if(e.target.id==='nav-search47'){ops47.navFilter=e.target.value;navigation();}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'&&state.user){e.preventDefault();void actions['quick-find47']();}});
Object.assign(actions,{
 'inbox-filter47':async b=>{ops47.inboxFilter=b.dataset.view;await go('inbox47');},
 'term-clear47':async()=>{const t=terminals46.tabs.get(terminals46.selected);if(t){t.term.clear();t.term.focus();}},
 'quick-find47':async()=>{modal('T\u00ecm nhanh \u00b7 Ctrl+K','<label>T\u00ean ch\u1ee9c n\u0103ng, IP ho\u1eb7c t\u00ean thi\u1ebft b\u1ecb<input id="quick-input47" autocomplete="off" placeholder="Nh\u1eadp \u0111\u1ec3 t\u00ecm..."></label><div id="quick-results47"></div>');const input=$('#quick-input47');input.focus();const rows=await api('/devices');if(!input.isConnected)return;const render=()=>{const q=input.value.toLocaleLowerCase('vi');const nav=[...$('#navigation').querySelectorAll('button.nav')].filter(b=>!(b.dataset.page==='runtime47'&&!isAdmin())&&!(b.dataset.page==='taskcenter47'&&!canWrite())&&b.textContent.toLocaleLowerCase('vi').includes(q));$('#quick-results47').innerHTML='<h3>Ch\u1ee9c n\u0103ng</h3><div class="quick-grid47">'+nav.slice(0,10).map(b=>button(tr[b.dataset.page],'quick-page47',{page:b.dataset.page})).join('')+'</div><h3>Thi\u1ebft b\u1ecb</h3><div class="quick-grid47">'+rows.filter(r=>[r.ip,r.hostname,r.mac].join(' ').toLocaleLowerCase('vi').includes(q)).slice(0,15).map(r=>button(r.ip+' '+(r.hostname||''),'workspace47',{id:r.id})).join('')+'</div>';};input.addEventListener('input',render);render();},
 'quick-page47':async b=>{$('#dialog').close();await go(b.dataset.page);},
 'workspace47':async b=>{ops47.deviceId=Number(b.dataset.id);$('#dialog').close();await go('device47');},
 'device-detail':async b=>actions['workspace47'](b),
 'select-all47':async()=>{for(const d of (state.cache||[]))ops47.selected.add(Number(d.id));await go('devices');},
 'select-clear47':async()=>{ops47.selected.clear();await go('devices');},
 'bulk-preview47':async b=>{const ids=b.dataset.id?[Number(b.dataset.id)]:[...ops47.selected];if(!ids.length)throw new Error('Ch\u1ecdn \u00edt nh\u1ea5t m\u1ed9t thi\u1ebft b\u1ecb.');const p=await api('/v47/plans/preview',{method:'POST',body:JSON.stringify({operation:b.dataset.op||'PING',inventory_ids:ids})});ops47.plan=p;modal('Xem tr\u01b0\u1edbc \u00b7 '+p.operation,note47('Ch\u01b0a g\u1eedi l\u1ec7nh t\u1edbi thi\u1ebft b\u1ecb. Ki\u1ec3m tra IP v\u00e0 ph\u1ea1m vi b\u00ean d\u01b0\u1edbi. K\u1ebf ho\u1ea1ch h\u1ebft h\u1ea1n sau 5 ph\u00fat.')+grid45(p.targets,[['IP','ip'],['T\u00ean','name'],['Inventory ID','inventory_id'],['Managed ID','managed_id'],['C\u1ea7n b\u1ed5 sung','blockers',v=>v.length?esc(v.join(', ')):'S\u1eb5n s\u00e0ng c\u1ea5u h\u00ecnh']],null,'plan47-grid')+note47(esc(p.effect))+ (p.can_run?button('X\u00e1c nh\u1eadn v\u00e0 ch\u1ea1y','plan-execute47',{},'primary'):note47('Ch\u01b0a th\u1ec3 ch\u1ea1y. '+esc(p.blockers.join(' \u00b7 ')),'warn')));},
 'plan-execute47':async()=>{const p=ops47.plan;if(!p?.token)throw new Error('H\u00e3y xem tr\u01b0\u1edbc k\u1ebf ho\u1ea1ch l\u1ea1i.');const token=p.token;p.token=null;const sourcePage=state.page;const r=await api('/v47/plans/execute',{method:'POST',body:JSON.stringify({token,authorized:true})});$('#dialog').close();trackQueuedJob(r,p.operation,sourcePage);},
 'device-terminal47':async b=>{const id=Number(b.dataset.id);await go('terminal');const f=$('#terminal-connect-form');if(f){f.elements.device_id.value=String(id);f.elements.device_id.dispatchEvent(new Event('change',{bubbles:true}));toast('Thi\u1ebft b\u1ecb \u0111\u00e3 ch\u1ecdn. Ki\u1ec3m tra giao th\u1ee9c v\u00e0 x\u00e1c nh\u1eadn tr\u01b0\u1edbc khi k\u1ebft n\u1ed1i.');}},
 'device-monitor47':async b=>{state.monitorDevice=Number(b.dataset.id);await go('monitoringx');},
 'ping-history47':async()=>{const runs=await api('/v47/ping-runs');modal('50 l\u1ea7n ch\u1ea1y Ping g\u1ea7n nh\u1ea5t',grid45(runs,[['B\u1eaft \u0111\u1ea7u','started_at'],['Tr\u1ea1ng th\u00e1i','status',badge],['Chu k\u1ef3','cycle'],['\u0110\u00e3 x\u1eed l\u00fd','done'],['T\u1ed5ng','total'],['K\u1ebft th\u00fac','finished_at'],['Ghi ch\u00fa','message']],null,'ping-runs47-grid'));},
 'diagnostics47':async()=>{const r=await api('/v47/diagnostics/export');r.browser={faults:ops47.faults,refresh_updates:refresh46.updates,refresh_skipped:refresh46.skipped,refresh_failures:refresh46.failures,viewport:{width:innerWidth,height:innerHeight},ui:'4.7.0'};download45(JSON.stringify(r,null,2),'NetworkAutomation-diagnostics.json','application/json');},
 'ack47':async b=>{await api('/v47/inbox/'+b.dataset.id+'/ack',{method:'POST',body:'{}'});await go('inbox47');},
 'silence47':async b=>{modal('T\u1ea1m \u1ea9n c\u1ea3nh b\u00e1o Ping',note47('Ch\u1ec9 \u00e1p d\u1ee5ng h\u1ed9p c\u1ea3nh b\u00e1o Ping c\u1ee7a Web. Kh\u00f4ng d\u1eebng \u0111o, kh\u00f4ng \u0111\u1ed5i email/Telegram hay c\u1ea3nh b\u00e1o c\u0169.')+form('silence47-form',`<input type="hidden" name="scope" value="${b.dataset.ip?'ip':'all'}"><input type="hidden" name="ip" value="${esc(b.dataset.ip||'')}">`+input('Th\u1eddi gian (ph\u00fat, 1\u201310080)','minutes','number',60)+input('L\u00fd do','reason','text',''),'X\u00e1c nh\u1eadn'));},
 'unsilence47':async b=>{await api('/v47/silences/'+b.dataset.id,{method:'DELETE'});await go('inbox47');},
 'density47':async()=>{document.body.classList.toggle('compact47');try{localStorage.setItem('na47_density',document.body.classList.contains('compact47')?'compact':'comfortable');}catch{}},
 'jobs-filter47':async b=>{ops47.jobsFilter=b.dataset.view;await go('taskcenter47');}
});
try{if(localStorage.getItem('na47_density')==='compact')document.body.classList.add('compact47');}catch{}
document.addEventListener('change',e=>{if(e.target.matches('[data-select-device47]')){const id=Number(e.target.dataset.selectDevice47);if(e.target.checked)ops47.selected.add(id);else ops47.selected.delete(id);const el=$('#selected-count47');if(el)el.textContent=ops47.selected.size;}});
forms['silence47-form']=async f=>{const v=vals(f);await api('/v47/silences',{method:'POST',body:JSON.stringify({...v,minutes:Number(v.minutes)})});$('#dialog').close();await go('inbox47');};
forms['policy47-form']=async f=>{const v=vals(f);await api('/v47/ping-policy',{method:'PUT',body:JSON.stringify({enabled:new FormData(f).has('enabled'),failures:Number(v.failures),recoveries:Number(v.recoveries),cooldown_seconds:Number(v.cooldown_seconds)})});toast('\u0110\u00e3 l\u01b0u ch\u00ednh s\u00e1ch c\u1ea3nh b\u00e1o Ping c\u1ee5c b\u1ed9.');};

/* A single overview, real counts only; no decorative simulated telemetry. */
pages.dashboard=async()=>{
 const [d,ping,inbox,alerts,cap,jobs]=await Promise.all([api('/dashboard'),api('/v45/ping'),api('/v47/inbox?view=active&limit=6'),api('/alerts?limit=6'),api('/v45/capabilities'),canWrite()?api('/jobs'):Promise.resolve([])]);
 const active=jobs.filter(x=>['Queued','Running'].includes(x.status)),failed=jobs.filter(x=>['Failed','Interrupted','CompletedWithErrors'].includes(x.status)),missing=Object.entries(cap.libraries).filter(([,v])=>!v).map(([k])=>k);
 return `<div class="device-hero47"><div><span class="eyebrow">CYBERSECURITY OPERATIONS</span><h2>T\u1ed5ng quan v\u1eadn h\u00e0nh</h2><p>Thi\u1ebft b\u1ecb, c\u1ea3nh b\u00e1o v\u00e0 t\u00e1c v\u1ee5 \u00b7 d\u1eef li\u1ec7u c\u00f3 th\u1eddi gian \u0111o.</p></div><div class="toolbar">${button('Gi\u00e1m s\u00e1t Ping','page',{page:'pingmonitor'},'primary')}${button('Thi\u1ebft b\u1ecb','page',{page:'devices'})}${button('LAN Readiness','page',{page:'lan'})}${isAdmin()?button('S\u1ee9c kh\u1ecfe h\u1ec7 th\u1ed1ng','page',{page:'runtime47'}):''}</div></div>`+
 (missing.length?note47('Ch\u01b0a c\u00e0i '+esc(missing.join(', '))+'. Ch\u1ea1y INSTALL_WEB.bat tr\u01b0\u1edbc khi d\u00f9ng ch\u1ee9c n\u0103ng ph\u1ee5 thu\u1ed9c. C\u00e1c trang kh\u00e1c v\u1eabn c\u00f3 th\u1ec3 s\u1eed d\u1ee5ng.','warn'):'')+
 `<div class="cards overview-cards47">${metric('Thi\u1ebft b\u1ecb',d.devices)}${metric('C\u00f3 ph\u1ea3n h\u1ed3i m\u1edbi',d.online,'green')}${metric('D\u1eef li\u1ec7u c\u0169',d.stale,'amber')}${metric('Ping ch\u01b0a x\u00e1c nh\u1eadn',inbox.unacknowledged,inbox.unacknowledged?'red':'')}${metric('T\u00e1c v\u1ee5 \u0111ang ch\u1ea1y',active.length)}${metric('C\u1ea7n ki\u1ec3m tra',failed.length,failed.length?'amber':'')}</div>`+
 `<div class="split47">${panel('Gi\u00e1m s\u00e1t Ping',`<div class="result-header">${badge(ping.state.status)}<strong>${ping.current_summary.measured}/${ping.state.total||ping.targets.length}</strong><span>Chu k\u1ef3 ${ping.state.cycle||0}</span></div><p>Ch\u1edd \u0111o: ${ping.current_summary.Pending} \u00b7 L\u1ed7i th\u1ef1c thi: ${ping.current_summary.Error}</p><p class="caption">Ch\u1ec9 b\u1ed9 \u0111\u1ebfm chu k\u1ef3 hi\u1ec7n t\u1ea1i; kh\u00f4ng g\u1ed9p k\u1ebft qu\u1ea3 c\u0169.</p>`,button('M\u1edf Ping','page',{page:'pingmonitor'}))}${panel('Ch\u1ea5t l\u01b0\u1ee3ng quan s\u00e1t',`<div class="checks47"><div><span>Ch\u01b0a x\u00e1c \u0111\u1ecbnh</span><strong>${fmt47(d.unknown)}</strong></div><div><span>V\u1ea5n \u0111\u1ec1 \u0111\u01b0\u1eddng m\u1ea1ng</span><strong>${fmt47(d.path_issue||0)}</strong></div><div><span>Kh\u00f4ng ph\u1ea3n h\u1ed3i</span><strong>${fmt47(d.no_reply||0)}</strong></div><div><span>Health samples</span><strong>${fmt47(d.health_samples)}</strong></div></div><p class="caption">Kh\u00f4ng c\u00f3 ph\u1ea3n h\u1ed3i ICMP kh\u00f4ng ch\u1ee9ng minh thi\u1ebft b\u1ecb t\u1eaft.</p>`,button('Ki\u1ec3m tra d\u1eef li\u1ec7u','page',{page:'diag'}))}</div>`+
 panel('Ping \u00b7 c\u1ea3nh b\u00e1o c\u1ea7n theo d\u00f5i',grid45(inbox.events,[['IP','ip'],['Tr\u1ea1ng th\u00e1i','status',badge],['B\u1eaft \u0111\u1ea7u','first_at'],['L\u1ea7n g\u1ea7n nh\u1ea5t','last_at'],['S\u1ed1 l\u1ea7n','occurrences']],null,'overview-inbox47'),button('M\u1edf h\u1ed9p c\u1ea3nh b\u00e1o','page',{page:'inbox47'}))+
 (canWrite()?panel('T\u00e1c v\u1ee5 g\u1ea7n nh\u1ea5t',grid45(jobs.slice(0,6),[['ID','id'],['Ch\u1ee9c n\u0103ng','operation'],['Tr\u1ea1ng th\u00e1i','status',badge],['\u0110\u00e3 x\u1eed l\u00fd','done'],['T\u1ed5ng','total'],['B\u1eaft \u0111\u1ea7u','created_at']],r=>button('K\u1ebft qu\u1ea3','job-detail',{id:r.id}),'overview-jobs47'),button('Trung t\u00e2m t\u00e1c v\u1ee5','page',{page:'taskcenter47'})):'')+
 panel('C\u1ea3nh b\u00e1o h\u1ec7 th\u1ed1ng g\u1ea7n \u0111\u00e2y',grid45(alerts,[['M\u1ee9c','severity',badge],['IP','ip'],['N\u1ed9i dung','message'],['Tr\u1ea1ng th\u00e1i','status']],null,'overview-alerts47'),button('Xem c\u1ea3nh b\u00e1o','page',{page:'alerts'}));
};

pages.devices=async()=>{
 const rows=await api('/devices');state.cache=rows;for(const id of ops47.selected)if(!rows.some(d=>d.id===id))ops47.selected.delete(id);
 const toolbar=canWrite()?`<div class="selection47"><strong>\u0110\u00e3 ch\u1ecdn <span id="selected-count47">${ops47.selected.size}</span></strong>${button('Ch\u1ecdn t\u1ea5t c\u1ea3','select-all47')}${button('B\u1ecf ch\u1ecdn','select-clear47')}${button('Ping','bulk-preview47',{op:'PING'},'primary')}${button('SNMP','bulk-preview47',{op:'SNMP'})}${button('SSH test','bulk-preview47',{op:'SSH_TEST'})}${isAdmin()?button('Backup','bulk-preview47',{op:'CONFIG_BACKUP'}):''}<small>Ping t\u1ed1i \u0111a 2048 IP / l\u01b0\u1ee3t; SNMP/SSH t\u1ed1i \u0111a 20; backup 5. Lu\u00f4n xem tr\u01b0\u1edbc.</small></div>`:'';
 const cols=[...(canWrite()?[['Ch\u1ecdn','id',v=>`<input type="checkbox" data-select-device47="${Number(v)}" aria-label="Ch\u1ecdn thi\u1ebft b\u1ecb ${Number(v)}" ${ops47.selected.has(Number(v))?'checked':''}>`]]:[]),['IP','ip'],['T\u00ean','hostname'],['MAC','mac'],['Quan s\u00e1t','status',badge],['D\u1eef li\u1ec7u','data_state',badge],['L\u1ea7n \u0111o','observed_at']];
 return `<div class="cards">${metric('Thi\u1ebft b\u1ecb',rows.length)}${metric('C\u00f3 ph\u1ea3n h\u1ed3i',rows.filter(d=>d.status==='Online').length,'green')}${metric('C\u1ea7n \u0111o l\u1ea1i',rows.filter(d=>d.data_state!=='FRESH').length,'amber')}${metric('Xung \u0111\u1ed9t danh t\u00ednh',rows.filter(d=>d.identity_conflict).length,'red')}</div>`+
 panel('Danh s\u00e1ch thi\u1ebft b\u1ecb',toolbar+grid45(rows,cols,r=>button('H\u1ed3 s\u01a1','workspace47',{id:r.id})+(isAdmin()?button('S\u1eeda','device-edit',{id:r.id})+(!r.managed_id&&!r.identity_conflict?button('Qu\u1ea3n tr\u1ecb','device-manage',{id:r.id}):'')+button('X\u00f3a','device-delete',{id:r.id},'danger'):''),'inventory47-grid'),isAdmin()?button('Th\u00eam thi\u1ebft b\u1ecb','device-add',{},'primary'):'');
};

/* Charts use recorded samples only; missing points split the path, not a fake zero. */
function spark47(samples,key,title){
 const rows=[...samples].reverse().slice(-60);const vals=rows.map(r=>r[key]??(key==='response'?r.response_ms:null));const numeric=vals.filter(v=>v!==null&&v!==''&&Number.isFinite(Number(v))).map(Number);
 if(!numeric.length)return panel(title,'<p class="muted">Ch\u01b0a c\u00f3 m\u1eabu \u0111o h\u1ee3p l\u1ec7.</p>');
 const max=Math.max(...numeric,1);let drawing=false;const path=vals.map((v,i)=>{if(v===null||v===''||!Number.isFinite(Number(v))){drawing=false;return '';}const x=12+i*456/Math.max(1,vals.length-1),y=106-Number(v)*86/max;const str=(drawing?'L':'M')+x.toFixed(1)+' '+y.toFixed(1);drawing=true;return str;}).join(' ');
 return panel(title,`<svg class="spark47" viewBox="0 0 480 122" role="img" aria-label="${esc(title)}: ${numeric.length} m\u1eabu h\u1ee3p l\u1ec7"><path d="M12 108 H468" class="spark-axis47"/><path d="${path}" class="spark-line47"/>${vals.map((v,i)=>v!==null&&v!==''&&Number.isFinite(Number(v))?`<circle cx="${12+i*456/Math.max(1,vals.length-1)}" cy="${106-Number(v)*86/max}" r="2" class="spark-dot47"/>`:'').join('')}</svg><div class="muted">${numeric.length}/${rows.length} m\u1eabu h\u1ee3p l\u1ec7 \u00b7 Min ${Math.min(...numeric).toFixed(1)} \u00b7 Max ${Math.max(...numeric).toFixed(1)} \u00b7 Kho\u1ea3ng tr\u1ed1ng = thi\u1ebfu ph\u00e9p \u0111o</div>`);
}
pages.device47=async()=>{
 if(!ops47.deviceId)return panel('Ch\u1ecdn thi\u1ebft b\u1ecb','<p>M\u1edf H\u1ed3 s\u01a1 t\u1eeb danh s\u00e1ch Thi\u1ebft b\u1ecb. Kh\u00f4ng t\u1ef1 ch\u1ecdn hay ch\u1ea1y l\u1ec7nh tr\u00ean m\u1ed9t thi\u1ebft b\u1ecb b\u1ea5t k\u1ef3.</p>'+button('Danh s\u00e1ch thi\u1ebft b\u1ecb','page',{page:'devices'}));
 const r=await api('/v47/devices/'+ops47.deviceId),d=r.device,p=r.prerequisites;
 const tool=button('Quay l\u1ea1i danh s\u00e1ch','page',{page:'devices'})+(canWrite()?button('Ki\u1ec3m tra Ping','bulk-preview47',{id:d.id,op:'PING'},'primary')+button('Ki\u1ec3m tra SNMP','bulk-preview47',{id:d.id,op:'SNMP'}):'')+(isAdmin()&&d.managed_id?button('Terminal','device-terminal47',{id:d.managed_id})+button('Backup','bulk-preview47',{id:d.id,op:'CONFIG_BACKUP'}):'')+(d.managed_id?button('T\u00e0i nguy\u00ean / c\u1ed5ng','device-monitor47',{id:d.managed_id}):'');
 const checks=[['Qu\u1ea3n tr\u1ecb',p.managed],['SSH credential',p.ssh_assigned],['SNMP credential',p.snmp_assigned],['SSH host key (c\u1ed5ng '+p.ssh_port+')',p.host_key_trusted]];
 return `<div class="device-hero47"><div><span class="eyebrow">DEVICE WORKSPACE</span><h2>${esc(d.hostname||d.ip)}</h2><p>${esc(d.ip)} \u00b7 ${esc(d.mac||'Ch\u01b0a c\u00f3 MAC')} \u00b7 Inventory #${d.id} / Managed ${d.managed_id?'#'+d.managed_id:'ch\u01b0a g\u00e1n'}</p></div>${badge(d.status)}${badge(d.data_state)}</div><div class="toolbar">${tool}</div>`+
 (d.identity_conflict?note47('C\u00f3 nhi\u1ec1u thi\u1ebft b\u1ecb qu\u1ea3n tr\u1ecb tr\u00f9ng IP. Ch\u01b0a cho ph\u00e9p t\u1ef1 ch\u1ecdn \u0111\u00edch SSH/SNMP.','warn'):'')+
 panel('\u0110i\u1ec1u ki\u1ec7n thao t\u00e1c',`<div class="checks47">${checks.map(([k,v])=>`<div><span>${esc(k)}</span>${badge(v?'Ready':'Setup')}</div>`).join('')}</div><p class="caption">Ki\u1ec3m tra c\u1ea5u h\u00ecnh, ch\u01b0a ph\u1ea3i x\u00e1c nh\u1eadn k\u1ebft n\u1ed1i thi\u1ebft b\u1ecb th\u1eadt. Host key b\u0103m c\u1ea7n ki\u1ec3m tra trong Credential & Trust.</p>`,isAdmin()?button('Credential & Trust','page',{page:'credentials'}):'')+
 `<div class="split47">${spark47(r.ping,'response','RTT (ms) \u00b7 m\u1eabu g\u1ea7n nh\u1ea5t')}${spark47(r.health,'cpu','CPU (%) \u00b7 m\u1eabu g\u1ea7n nh\u1ea5t')}</div>`+
 panel('L\u1ecbch s\u1eed Ping (t\u1ed1i \u0111a 120 m\u1eabu)',grid45(r.ping,[['K\u1ebft qu\u1ea3','status',badge],['RTT ms','response',(_,x)=>number47(x.response??x.response_ms)],['Th\u1eddi gian','ping_time',(_,x)=>fmt47(x.ping_time||x.created_at)]],null,'device-ping47'))+
 panel('C\u1ed5ng m\u1ea1ng \u00b7 quan s\u00e1t \u0111\u00e3 l\u01b0u',grid45(r.ports,[['IfIndex','ifindex'],['T\u00ean','ifname'],['Tr\u1ea1ng th\u00e1i','oper_status'],['T\u1ed1c \u0111\u1ed9 bps','speed_bps'],['L\u1ed7i v\u00e0o','in_errors'],['L\u1ed7i ra','out_errors'],['\u0110\u00e3 \u0111o','created_at']],null,'device-ports47'))+
 panel('C\u1ea3nh b\u00e1o thi\u1ebft b\u1ecb',grid45(r.alerts,[['M\u1ee9c','severity',badge],['N\u1ed9i dung','message'],['Tr\u1ea1ng th\u00e1i','status'],['Th\u1eddi gian','created_at']],null,'device-alerts47'))+
 panel('Backup \u00b7 ch\u1ec9 metadata',grid45(r.backups,[['ID','id'],['Thi\u1ebft b\u1ecb','device_name'],['Ngu\u1ed3n','source'],['Dung l\u01b0\u1ee3ng','size_bytes',bytes47],['T\u1ea1o l\u00fac','created_at']],null,'device-backups47')+note47('Gh\u00e9p backup theo IP ho\u1eb7c nh\u00e3n thi\u1ebft b\u1ecb duy nh\u1ea5t. Ph\u1ea3i ki\u1ec3m tra l\u1ea1i tr\u01b0\u1edbc khi restore; kh\u00f4ng t\u1ef1 kh\u00f4i ph\u1ee5c.'));
};

pingStatus45=function(d){const s=d.state,c=d.current_summary;const rows=c||{Online:0,Offline:0,Unknown:0,Error:0,Pending:s.total||0,measured:0};return `<div class="result-header">${badge(s.status)}<b>${rows.measured}/${s.total||0}</b><span>Chu k\u1ef3 ${s.cycle||0}</span></div><div class="progress-line"><progress value="${rows.measured}" max="${s.total||1}"></progress><span>${s.next_run_at?'L\u01b0\u1ee3t ti\u1ebfp: '+esc(new Date(s.next_run_at).toLocaleTimeString()):esc(s.message||'')}</span></div><p class="caption">K\u1ebft qu\u1ea3 <b>chu k\u1ef3 hi\u1ec7n t\u1ea1i</b>. K\u1ebft qu\u1ea3 c\u0169 ch\u1ec9 hi\u1ec3n th\u1ecb trong b\u1ea3ng, kh\u00f4ng c\u1ed9ng v\u00e0o b\u1ed9 \u0111\u1ebfm n\u00e0y.</p><div class="cards ping-cards47">${metric('C\u00f3 ph\u1ea3n h\u1ed3i',rows.Online,'green')}${metric('Kh\u00f4ng ph\u1ea3n h\u1ed3i',rows.Offline,'amber')}${metric('Ch\u01b0a x\u00e1c \u0111\u1ecbnh',rows.Unknown)}${metric('L\u1ed7i th\u1ef1c thi',rows.Error,'red')}${metric('Ch\u1edd \u0111o',rows.Pending)}</div><div class="muted">B\u1eaft \u0111\u1ea7u: ${fmt47(s.cycle_started_at||s.started_at)} \u00b7 K\u1ebft th\u00fac: ${fmt47(s.finished_at)}</div>`;};
pingRows45=function(d){return grid45(d.targets,[['IP','ip'],['T\u00ean','name'],['ICMP','status',badge],['RTT (ms)','response',number47],['L\u1ea7n \u0111o','measurement_cycle',v=>badge({CURRENT:'Hi\u1ec7n t\u1ea1i',PREVIOUS:'L\u01b0\u1ee3t tr\u01b0\u1edbc',UNMEASURED:'Ch\u01b0a \u0111o'}[v]||v)],['Th\u1eddi gian','observed_at'],['D\u1eef li\u1ec7u','data_state',badge],['Di\u1ec5n gi\u1ea3i','error']],canWrite()&&!d.state.running?r=>button('S\u1eeda','ping-target-edit',{ip:r.ip})+button('X\u00f3a','ping-target-delete',{ip:r.ip},'danger'):null,'ping-target-grid');};
const originalPing47=pages.pingmonitor;
pages.pingmonitor=async()=>await originalPing47()+(canWrite()?`<div class="toolbar">${button('L\u1ecbch s\u1eed l\u1ea7n ch\u1ea1y','ping-history47')}${button('H\u1ed9p c\u1ea3nh b\u00e1o Ping','page',{page:'inbox47'})}</div>`:'');

pages.inbox47=async()=>{
 const [d,p]=await Promise.all([api('/v47/inbox?view='+ops47.inboxFilter),api('/v47/ping-policy')]);
 return note47('C\u1ea3nh b\u00e1o c\u1ee5c b\u1ed9 t\u1eeb Gi\u00e1m s\u00e1t Ping: gom theo IP, ch\u1edd nhi\u1ec1u l\u1ea7n l\u1ed7i li\u00ean ti\u1ebfp v\u00e0 ghi nh\u1eadn ph\u1ee5c h\u1ed3i. Kh\u00f4ng ph\u1ea3n h\u1ed3i ICMP kh\u00f4ng ch\u1ee9ng minh thi\u1ebft b\u1ecb t\u1eaft. Ch\u01b0a g\u1eedi th\u00f4ng b\u00e1o ra email/Telegram.')+
 `<div class="cards">${metric('\u0110ang m\u1edf',d.summary.open||0,'amber')}${metric('Ch\u01b0a x\u00e1c nh\u1eadn',d.unacknowledged)}${metric('\u0110\u00e3 ph\u1ee5c h\u1ed3i',d.summary.recovered||0,'green')}${metric('Kho\u1ea3ng t\u1ea1m \u1ea9n',d.silences.length)}</div>`+
 panel('200 s\u1ef1 ki\u1ec7n g\u1ea7n nh\u1ea5t',`<div class="toolbar">${[['active','C\u1ea7n theo d\u00f5i'],['silenced','\u0110ang t\u1ea1m \u1ea9n'],['recovered','\u0110\u00e3 ph\u1ee5c h\u1ed3i'],['all','T\u1ea5t c\u1ea3']].map(([view,label])=>button(label,'inbox-filter47',{view},ops47.inboxFilter===view?'active':'')).join('')}</div>`+grid45(d.events,[['IP','ip'],['Tr\u1ea1ng th\u00e1i','status',badge],['L\u1ea7n \u0111\u1ea7u','first_at'],['G\u1ea7n nh\u1ea5t','last_at'],['S\u1ed1 quan s\u00e1t l\u1ed7i','occurrences'],['X\u00e1c nh\u1eadn','acknowledged_at'],['T\u1ea1m \u1ea9n','silenced_now',v=>v?'C\u00f3':'Kh\u00f4ng']],canWrite()?r=>(!r.acknowledged_at?button('X\u00e1c nh\u1eadn','ack47',{id:r.id}):'')+(r.status==='open'?button('T\u1ea1m \u1ea9n','silence47',{ip:r.ip}):''):null,'inbox47-grid'))+
 panel('T\u1ea1m \u1ea9n \u0111ang hi\u1ec7u l\u1ef1c',grid45(d.silences,[['Ph\u1ea1m vi','scope'],['IP','ip'],['L\u00fd do','reason'],['H\u1ebft h\u1ea1n','until_epoch',v=>esc(new Date(v*1000).toLocaleString())]],canWrite()?r=>(isAdmin()||r.actor_id===state.user.id)?button('H\u1ee7y t\u1ea1m \u1ea9n','unsilence47',{id:r.id},'danger'):'':null,'silences47-grid'),isAdmin()?button('T\u1ea1m \u1ea9n to\u00e0n b\u1ed9','silence47'): '')+
 (isAdmin()?panel('Ch\u00ednh s\u00e1ch Ping \u00b7 kh\u00f4ng \u0111\u1ed5i c\u1ea3nh b\u00e1o c\u0169',form('policy47-form',check45('enabled','B\u1eadt h\u1ed9p c\u1ea3nh b\u00e1o Ping',p.enabled)+input('L\u1ed7i li\u00ean ti\u1ebfp','failures','number',p.failures)+input('Ph\u1ee5c h\u1ed3i li\u00ean ti\u1ebfp','recoveries','number',p.recoveries)+input('Kho\u1ea3ng c\u00e1ch m\u1edf l\u1ea1i (gi\u00e2y)','cooldown_seconds','number',p.cooldown_seconds),'L\u01b0u ch\u00ednh s\u00e1ch')):'');
};
pages.runtime47=async()=>{
 if(!isAdmin())return note47('Ch\u1ec9 Admin \u0111\u01b0\u1ee3c xem ch\u1ea9n \u0111o\u00e1n h\u1ec7 th\u1ed1ng.','warn');
 const d=await api('/v47/runtime');const assets=d.assets.every(x=>x.present);
 return `<div class="cards">${metric('Server uptime',duration47(d.uptime_seconds))}${metric('Worker',d.worker_ready?'S\u1eb5n s\u00e0ng':'D\u1eebng',d.worker_ready?'green':'red')}${metric('T\u00e1c v\u1ee5 ch\u1edd / ch\u1ea1y',(d.jobs.Queued||0)+' / '+(d.jobs.Running||0))}${metric('Dung l\u01b0\u1ee3ng tr\u1ed1ng',bytes47(d.storage.free_bytes),d.storage.low_space?'red':'green')}</div>`+
 (d.storage.low_space?note47('Dung l\u01b0\u1ee3ng tr\u1ed1ng d\u01b0\u1edbi 512 MB. Ki\u1ec3m tra l\u01b0u tr\u1eef tr\u01b0\u1edbc khi ch\u1ea1y th\u00eam t\u00e1c v\u1ee5.','warn'):'')+
 panel('T\u00ecnh tr\u1ea1ng v\u1eadn h\u00e0nh',`<div class="checks47">${[['Giao di\u1ec7n',assets?'\u0110\u1ee7 '+d.assets.length+' file':'Thi\u1ebfu file'],['Scheduler',d.scheduler_alive?'\u0110ang ch\u1ea1y':'\u0110\u00e3 d\u1eebng'],['L\u1ecbch \u0111\u00e3 b\u1eadt',d.enabled_schedules],['Ping executable',d.ping_executable?'\u0110\u00e3 c\u00f3':'Ch\u01b0a c\u00f3'],['Database',bytes47(d.database.bytes)+' / '+d.database.journal_mode],['Kh\u1edfi \u0111\u1ed9ng',d.started_at]].map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>`,button('T\u1ea3i ch\u1ea9n \u0111o\u00e1n \u0111\u00e3 l\u1ecdc','diagnostics47',{},'primary'))+
 `<div class="split47">${panel('Th\u01b0 vi\u1ec7n',grid45(Object.entries(d.libraries).map(([name,version])=>({name,version:version||'CH\u01afA C\u00c0I'})),[['Th\u01b0 vi\u1ec7n','name'],['Phi\u00ean b\u1ea3n','version']],null,'libraries47-grid'))}${panel('D\u1eef li\u1ec7u \u0111ang l\u01b0u',grid45(d.tables,[['B\u1ea3ng','table'],['B\u1ea3n ghi','rows']],null,'tables47-grid'),button('L\u01b0u tr\u1eef / sao l\u01b0u','page',{page:'production'}))}</div>`+
 panel('L\u1ed7i / request ch\u1eadm g\u1ea7n \u0111\u00e2y',grid45(d.recent_errors,[['Th\u1eddi gian','at'],['Method','method'],['Route','route'],['HTTP','status'],['ms','duration_ms'],['M\u00e3 tra c\u1ee9u','request_id']],null,'errors47-grid')+note47('Ch\u1ec9 metadata: kh\u00f4ng body, query, m\u1eadt kh\u1ea9u hay n\u1ed9i dung terminal. B\u1ed9 \u0111\u1ebfm request t\u00ednh t\u1eeb l\u1ea7n kh\u1edfi \u0111\u1ed9ng n\u00e0y.'))+
 panel('Ki\u1ec3m tra file ph\u00e1t h\u00e0nh',grid45(d.assets,[['File','name'],['C\u00f3 file','present',v=>badge(v?'Ready':'Missing')],['SHA-256','sha256']],null,'assets47-grid'));
};
pages.taskcenter47=async()=>{
 if(!canWrite())return note47('T\u00e0i kho\u1ea3n ch\u1ec9 xem kh\u00f4ng \u0111\u01b0\u1ee3c truy c\u1eadp t\u00e1c v\u1ee5 qu\u1ea3n tr\u1ecb.');
 const [all,ping]=await Promise.all([api('/jobs'),api('/v45/ping')]);
 const running=['Queued','Running'],failed=['Failed','CompletedWithErrors','Interrupted'];
 const rows=all.filter(j=>ops47.jobsFilter==='running'?running.includes(j.status):ops47.jobsFilter==='failed'?failed.includes(j.status):true);
 return note47('Kh\u00f4ng t\u1ef1 ch\u1ea1y l\u1ea1i t\u00e1c v\u1ee5 gi\u00e1n \u0111o\u1ea1n. Completed l\u00e0 k\u1ebft th\u00fac th\u1ef1c thi, kh\u00f4ng c\u00f3 ngh\u0129a m\u1ecdi thi\u1ebft b\u1ecb \u0111\u1ec1u t\u1ed1t.')+
 `<div class="cards">${metric('\u0110ang ch\u1edd / ch\u1ea1y',all.filter(j=>running.includes(j.status)).length)}${metric('C\u1ea7n ki\u1ec3m tra',all.filter(j=>failed.includes(j.status)).length,'amber')}${metric('Ping',ping.state.status)}${metric('Hi\u1ec3n th\u1ecb',all.length+' g\u1ea7n nh\u1ea5t')}</div>`+
 panel('L\u1ecbch s\u1eed t\u00e1c v\u1ee5',`<div class="toolbar">${[['all','T\u1ea5t c\u1ea3'],['running','\u0110ang ch\u1ea1y'],['failed','L\u1ed7i / gi\u00e1n \u0111o\u1ea1n']].map(([view,label])=>button(label,'jobs-filter47',{view},ops47.jobsFilter===view?'active':'')).join('')}</div>`+grid45(rows,[['ID','id'],['Ch\u1ee9c n\u0103ng','operation'],['Ng\u01b0\u1eddi ch\u1ea1y','actor'],['Tr\u1ea1ng th\u00e1i','status',badge],['\u0110\u00e3 x\u1eed l\u00fd','done'],['T\u1ed5ng','total'],['B\u1eaft \u0111\u1ea7u','created_at'],['K\u1ebft th\u00fac','finished_at']],r=>button('K\u1ebft qu\u1ea3','job-detail',{id:r.id})+(running.includes(r.status)&&(isAdmin()||r.actor===state.user.username)?button('D\u1eebng','job-cancel',{id:r.id},'danger'):''),'tasks47-grid'));
};

/* Keep expensive active-page polling bounded; use a backoff after failures. */
window.addEventListener('na46:logout',()=>{ops47.deviceId=0;ops47.selected.clear();ops47.plan=null;ops47.faults=[];ops47.navFilter='';ops47.inboxFilter='active';const n=$('#nav-search47');if(n)n.value='';});
const oldClose47=actions['close-modal'];actions['close-modal']=async()=>{if([...$('#dialog').querySelectorAll('form')].some(f=>refresh46.dirty.has(f))&&!confirm('B\u1ecf thay \u0111\u1ed5i ch\u01b0a l\u01b0u?'))return;await oldClose47();};
for(const name of ['input','change'])document.addEventListener(name,e=>{const f=e.target.closest('#dialog form');if(f)refresh46.dirty.add(f);});
$('#dialog').addEventListener('cancel',e=>{if([...$('#dialog').querySelectorAll('form')].some(f=>refresh46.dirty.has(f))&&!confirm('B\u1ecf thay \u0111\u1ed5i ch\u01b0a l\u01b0u?'))e.preventDefault();});
window.addEventListener('na46:ready',()=>{filterNavigation47();});

}
