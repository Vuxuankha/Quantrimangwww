'use strict';
/* Workbench UI. Existing pages continue to use the same APIs and shared engines. */
const wb45 = {
  grids: new Map(), gridSerial: 0, operations: new Map(), selectedJob: new Map(),
  watchers: new Map(), ping: null, auto: null, activeRun: '', autoSteps: [],
  followAuto: true, pollBusy: false, pageScroll: new Map(), lastAutoStatus: '',
  labels: {
    status: 'Tr\u1ea1ng th\u00e1i', ip: 'IP', host: 'Host', name: 'T\u00ean',
    hostname: 'T\u00ean thi\u1ebft b\u1ecb', device_id: 'ID thi\u1ebft b\u1ecb',
    success: 'K\u1ebft qu\u1ea3', detail: 'Di\u1ec5n gi\u1ea3i', error: 'L\u1ed7i',
    response: 'RTT (ms)', latency_ms: 'RTT (ms)', packet_loss: 'M\u1ea5t g\u00f3i (%)',
    observed_at: 'Th\u1eddi gian \u0111o', created_at: 'Th\u1eddi gian',
    path_state: '\u0110\u01b0\u1eddng m\u1ea1ng', ping_state: 'ICMP',
    route_class: 'Lo\u1ea1i route', next_hop: 'Gateway', interface: 'Card m\u1ea1ng',
    subnet: 'Subnet', targets: 'S\u1ed1 IP', online: 'C\u00f3 ph\u1ea3n h\u1ed3i',
    task: 'B\u01b0\u1edbc x\u1eed l\u00fd', message: 'N\u1ed9i dung',
    result: 'Chi ti\u1ebft', results: 'K\u1ebft qu\u1ea3 t\u1eebng thi\u1ebft b\u1ecb',
    summary: 'T\u1ed5ng h\u1ee3p', subnets: 'T\u1ed5ng h\u1ee3p theo subnet',
    REACHABLE: 'C\u00f3 ph\u1ea3n h\u1ed3i', NO_ROUTE: 'Kh\u00f4ng c\u00f3 route',
    PATH_UNVERIFIED: 'Ch\u01b0a x\u00e1c minh \u0111\u01b0\u1eddng m\u1ea1ng',
    NO_ICMP_REPLY: 'Kh\u00f4ng ph\u1ea3n h\u1ed3i ICMP',
    cpu: 'CPU (%)', memory: 'RAM (%)', ram: 'RAM (%)',
    data_state: '\u0110\u1ed9 m\u1edbi d\u1eef li\u1ec7u', profile: 'Profile',
    count: 'S\u1ed1 b\u1ea3n ghi', state: 'Tr\u1ea1ng th\u00e1i', steps: 'C\u00e1c b\u01b0\u1edbc',
    note: 'Ghi ch\u00fa', conflict: 'Xung \u0111\u1ed9t MAC', mac: 'MAC'
  }
};
const label45 = key => wb45.labels[key] || String(key).replace(/_/g, ' ');
const primitive45 = v => v === null || v === undefined || typeof v !== 'object';
const rawTable45 = table;
function scalar45(v, key = '') {
  if (v === null || v === undefined || v === '') return '<span class="muted">\u2014</span>';
  if (typeof v === 'boolean') return badge(v ? 'OK' : 'Failed');
  if (/^(status|state|path_state|ping_state|severity|data_state)$/.test(key)) return badge(v);
  if (typeof v === 'object') return `<details class="cell-detail"><summary>Chi ti\u1ebft</summary>${structured45(v, '', 1, false)}</details>`;
  return esc(v);
}
function flatten45(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return {value: row};
  if (row.result && typeof row.result === 'object' && !Array.isArray(row.result)) {
    const nested = row.result;
    return {...row, ...nested, result: Object.fromEntries(Object.entries(nested).filter(([,v]) => !primitive45(v)))};
  }
  return row;
}
function gridMarkup45(id) {
  const g = wb45.grids.get(id);
  if (!g) return '';
  const term = g.filter.toLocaleLowerCase();
  let rows = g.rows.filter(r => !term || JSON.stringify(r).toLocaleLowerCase().includes(term));
  if (g.sortKey) rows.sort((a,b) => String(a[g.sortKey] ?? '').localeCompare(String(b[g.sortKey] ?? ''), 'vi', {numeric:true}) * g.direction);
  const total = rows.length, maxPage = Math.max(1, Math.ceil(total / g.size));
  g.page = Math.max(0, Math.min(g.page, maxPage - 1));
  const shown = rows.slice(g.page*g.size,(g.page+1)*g.size);
  const tools = `<div class="grid-tools"><label class="search-label">T\u00ecm / l\u1ecdc<input data-grid-filter="${id}" value="${esc(g.filter)}" placeholder="IP, t\u00ean, tr\u1ea1ng th\u00e1i..." aria-label="T\u00ecm trong b\u1ea3ng"></label><span class="muted">${total} / ${g.rows.length} d\u00f2ng</span>${button('Xu\u1ea5t CSV','grid-export',{grid:id})}</div>`;
  const body = `<div class="scroll"><table><thead><tr>${g.cols.map(c=>`<th><button class="sort-button" data-action="grid-sort" data-grid="${id}" data-key="${esc(c[1])}">${esc(c[0])}${g.sortKey===c[1]?(g.direction===1?' \u2191':' \u2193'):''}</button></th>`).join('')}${g.rowActions?'<th>Thao t\u00e1c</th>':''}</tr></thead><tbody>${shown.map(r=>`<tr>${g.cols.map(c=>`<td>${c[2]?c[2](r[c[1]],r):scalar45(r[c[1]],c[1])}</td>`).join('')}${g.rowActions?`<td class="actions">${g.rowActions(r)}</td>`:''}</tr>`).join('') || `<tr><td colspan="${g.cols.length+(g.rowActions?1:0)}" class="muted">Kh\u00f4ng c\u00f3 d\u1eef li\u1ec7u ph\u00f9 h\u1ee3p.</td></tr>`}</tbody></table></div>`;
  const pager = `<div class="grid-pager"><span>${total?g.page*g.size+1:0}\u2013${Math.min((g.page+1)*g.size,total)} / ${total}</span>${button('\u2190 Tr\u01b0\u1edbc','grid-prev',{grid:id})}<span>Trang ${g.page+1}/${maxPage}</span>${button('Sau \u2192','grid-next',{grid:id})}</div>`;
  return tools+body+pager;
}
function grid45(rows, cols, rowActions, key='') {
  // A stable key preserves filters / pagination during live updates.
  const id=key || 'grid45-'+(++wb45.gridSerial);
  const previous=wb45.grids.get(id);
  wb45.grids.set(id,{rows:rows || [],cols,rowActions,filter:previous?.filter || '',page:previous?.page || 0,size:50,sortKey:previous?.sortKey || '',direction:previous?.direction || 1});
  // Bound detached-table memory; active tables are never removed.
  if (wb45.grids.size>250) for (const k of wb45.grids.keys()) { if (!document.getElementById(k) && k!==id) {wb45.grids.delete(k);break;} }
  return `<div class="data-grid" id="${id}">${gridMarkup45(id)}</div>`;
}
function repaintGrid45(id, restoreInput=false) {
  const el=document.getElementById(id);if(!el)return;
  const pos=restoreInput?el.querySelector('input')?.selectionStart:null;
  el.innerHTML=gridMarkup45(id);
  if(restoreInput){const inp=el.querySelector('input');inp?.focus();if(pos!=null)inp?.setSelectionRange(pos,pos);}
}
// All original module pages gain searchable, paginated tables without a rewrite.
table = (rows,cols,rowActions) => grid45(rows,cols,rowActions);
function rows45(rows,key='') {
  const normalized=rows.map(flatten45), keys=[...new Set(normalized.flatMap(r=>Object.keys(r)))];
  const preferred=['device_id','ip','host','name','hostname','task','status','success','path_state','ping_state','response','latency_ms','packet_loss','detail','message','error','observed_at','created_at'];
  keys.sort((a,b)=>{const rank=x=>preferred.includes(x)?preferred.indexOf(x):preferred.length;return rank(a)-rank(b);});
  return grid45(normalized,keys.map(k=>[label45(k),k,(v)=>scalar45(v,k)]),null,key);
}
function structured45(value, title='', depth=0, debug=true) {
  if(value===null||value===undefined)return '<p class="muted">Ch\u01b0a c\u00f3 k\u1ebft qu\u1ea3.</p>';
  if(depth>4)return `<details><summary>Xem th\u00eam</summary><pre class="technical-json">${esc(JSON.stringify(value,null,2))}</pre></details>`;
  if(Array.isArray(value))return value.length?rows45(value):'<p class="muted">Kh\u00f4ng c\u00f3 b\u1ea3n ghi.</p>';
  if(typeof value!=='object')return `<div class="text-result">${esc(String(value))}</div>`;
  const out=[];
  const download=value.download_url;
  if(typeof download==='string' && /^\/api\/downloads\/[A-Za-z0-9_-]+$/.test(download))out.push(`<a class="download-link" href="${esc(download)}" download>\u2193 T\u1ea3i ${esc(value.name||'k\u1ebft qu\u1ea3')}</a>`);
  if(value.summary && typeof value.summary==='object' && !Array.isArray(value.summary)){
    out.push(`<div class="cards result-metrics">${Object.entries(value.summary).filter(([,v])=>primitive45(v)).map(([k,v])=>metric(label45(k),v,k==='REACHABLE'||k==='OK'?'green':k==='ERROR'?'red':'')).join('')}</div>`);
  }
  if(value.results && value.summary && ('PATH_UNVERIFIED' in value.summary))out.push('<div class="inline-notice">Ch\u01b0a x\u00e1c minh \u0111\u01b0\u1eddng m\u1ea1ng / kh\u00f4ng ph\u1ea3n h\u1ed3i ICMP <b>kh\u00f4ng kh\u1eb3ng \u0111\u1ecbnh thi\u1ebft b\u1ecb \u0111\u00e3 t\u1eaft</b>. Xem route, gateway v\u00e0 th\u1eddi gian \u0111o trong b\u1ea3ng.</div>');
  const scalars=Object.entries(value).filter(([k,v])=>primitive45(v)&&!['download_url','name'].includes(k));
  if(value.name && !download)scalars.unshift(['name',value.name]);
  if(scalars.length)out.push(`<div class="result-fields">${scalars.map(([k,v])=>`<div><span>${esc(label45(k))}</span><strong>${scalar45(v,k)}</strong></div>`).join('')}</div>`);
  for(const [key,v] of Object.entries(value)){
    if(primitive45(v)||key==='summary')continue;
    const rendered=Array.isArray(v)?rows45(v):structured45(v,key,depth+1,false);
    out.push(`<section class="result-section"><h4>${esc(label45(key))}</h4>${rendered}</section>`);
  }
  if(debug)out.push(`<details class="technical-details"><summary>D\u1eef li\u1ec7u k\u1ef9 thu\u1eadt (JSON) \u2014 ch\u1ec9 d\u00f9ng khi ch\u1ea9n \u0111o\u00e1n</summary><pre class="technical-json">${esc(JSON.stringify(value,null,2))}</pre></details>`);
  return out.join('');
}
kv = d => structured45(d,'',1,false);
jobResultPreview = r => structured45(r);
const oldBadge45 = badge;
badge = v => {const text=String(v??'Unknown');return `<span class="badge ${esc(text.toLowerCase().replace(/[^a-z]/g,''))}" title="${esc(text)}">${esc(label45(text))}</span>`;};

Object.assign(actions,{
  'grid-prev':async b=>{const g=wb45.grids.get(b.dataset.grid);if(g){g.page--;repaintGrid45(b.dataset.grid);}},
  'grid-next':async b=>{const g=wb45.grids.get(b.dataset.grid);if(g){g.page++;repaintGrid45(b.dataset.grid);}},
  'grid-sort':async b=>{const g=wb45.grids.get(b.dataset.grid);if(g){g.direction=g.sortKey===b.dataset.key?-g.direction:1;g.sortKey=b.dataset.key;repaintGrid45(b.dataset.grid);}},
  'grid-export':async b=>{const g=wb45.grids.get(b.dataset.grid);if(!g)return;const rows=g.rows.filter(r=>!g.filter||JSON.stringify(r).toLocaleLowerCase().includes(g.filter.toLocaleLowerCase()));const safe=v=>{let x=typeof v==='object'?JSON.stringify(v??''):String(v??'');if(/^[\s]*[=+@-]/.test(x))x="'"+x;return '"'+x.replace(/"/g,'""')+'"';};const csv=[g.cols.map(c=>safe(c[0])).join(','),...rows.map(r=>g.cols.map(c=>safe(r[c[1]])).join(','))].join('\r\n');download45('\uFEFF'+csv,'NetworkAutomation-'+state.page+'.csv','text/csv;charset=utf-8');}
});
function download45(content,name,type){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([content],{type}));a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
document.addEventListener('input',e=>{const id=e.target.dataset.gridFilter;if(!id)return;const g=wb45.grids.get(id);if(g){g.filter=e.target.value;g.page=0;repaintGrid45(id,true);}});

/* Page-owned job results: navigation never cancels tracking or moves the result. */
function saveJobs45(){if(!state.user)return;try{sessionStorage.setItem('na45_jobs_'+state.user.id,JSON.stringify([...wb45.operations.values()].flat().filter(o=>o.job.id).map(o=>({id:o.job.id,page:o.page,label:o.label})).slice(-50)));}catch{}}
function selectOperation45(page,op){const list=wb45.operations.get(page)||[];const existing=list.find(x=>x.job.id===op.job.id);if(!existing){list.push(op);if(list.length>8)list.shift();wb45.operations.set(page,list);}else{Object.assign(existing,op);}wb45.selectedJob.set(page,op.job.id);saveJobs45();}
renderOperationResult = function(){
  const host=$('#operation-result');if(!host)return;
  const list=wb45.operations.get(state.page)||[];
  const op=list.find(x=>x.job.id===wb45.selectedJob.get(state.page))||list[list.length-1];
  if(!op){host.innerHTML='';host.classList.add('hidden');return;}
  const j=op.job;const finished=terminalJobStates.has(j.status)||j.status==='Stopped';
  const tools=(!finished&&j.id?button('D\u1eebng t\u00e1c v\u1ee5','job-cancel',{id:j.id},'danger'):'')+button('\u1ea8n k\u1ebft qu\u1ea3','operation-dismiss');
  const tabs=list.length>1?`<div class="result-tabs">${list.map(x=>button('#'+x.job.id+' '+x.label,'result-select',{id:x.job.id},x===op?'active':'')).join('')}</div>`:'';
  const progress=j.total?`<div class="progress-line"><progress value="${Number(j.done)||0}" max="${Number(j.total)||1}"></progress><span>${j.done||0}/${j.total}</span></div>`:'';
  const waiting=`<div class="operation-wait"><span class="spinner-inline"></span> \u0110ang x\u1eed l\u00fd. C\u00f3 th\u1ec3 chuy\u1ec3n trang; k\u1ebft qu\u1ea3 v\u1eabn l\u01b0u \u1edf \u0111\u00e2y.</div>`;
  window.patchHTML46(host,panel('K\u1ebft qu\u1ea3: '+(tr[state.page]||state.page),tabs+`<div class="result-header"><b>${esc(op.label)}</b>${badge(j.status)}<span class="muted">#${esc(j.id)} \u00b7 ${esc(j.finished_at||j.created_at||'')}</span></div>`+progress+(op.pollError?`<div class="error">${esc(op.pollError)} \u2014 \u0111ang th\u1eed k\u1ebft n\u1ed1i l\u1ea1i.</div>`:'')+(j.error?`<div class="error">${esc(j.error)}</div>`:'')+(finished?structured45(j.result):waiting),tools));
  host.classList.remove('hidden');
};
watchJob = function(id,page,label=''){
  id=Number(id);if(!id)return;
  const existing=(wb45.operations.get(page)||[]).find(x=>x.job.id===id);
  const op=existing||{page,label:label||'Task',job:{id,operation:label,status:'Queued',done:0,total:0}};
  selectOperation45(page,op);renderOperationResult();
  if(wb45.watchers.has(id))return;
  const observer={userId:state.user?.id,timer:null};wb45.watchers.set(id,observer);
  const alive=()=>state.user?.id===observer.userId&&wb45.watchers.get(id)===observer;
  const poll=async()=>{
    if(!alive())return;
    try{
      const j=await api('/jobs/'+id);if(!alive())return;op.job=j;op.pollError='';
      if(state.page===page)renderOperationResult();
      if(terminalJobStates.has(j.status)){
        wb45.watchers.delete(id);saveJobs45();
        if(state.page===page)toast(j.status==='Completed'?'T\u00e1c v\u1ee5 \u0111\u00e3 ho\u00e0n t\u1ea5t.':'T\u00e1c v\u1ee5 k\u1ebft th\u00fac: '+j.status,j.status!=='Completed');
        if(state.page===page)await window.refreshPage46?.(page);
        return;
      }
    }catch(e){if(!alive())return;op.pollError=e.message;if(state.page===page)renderOperationResult();}
    if(alive())observer.timer=setTimeout(poll,op.pollError?4000:1000);
  };
  poll();
};
trackQueuedJob = (r,label,page=state.page)=>{const id=Number(r?.job_id||r?.id);if(!id)throw new Error('API kh\u00f4ng tr\u1ea3 m\u00e3 t\u00e1c v\u1ee5.');watchJob(id,page,label);toast('\u0110\u00e3 g\u1eedi t\u00e1c v\u1ee5 #'+id);};
function immediate45(result,label,page=state.page){const op={page,label,job:{id:'local-'+Date.now(),status:result?.success===false?'CompletedWithErrors':'Completed',created_at:new Date().toISOString(),result}};selectOperation45(page,op);renderOperationResult();}
Object.assign(actions,{
  'operation-dismiss':async()=>{const list=wb45.operations.get(state.page)||[];const id=wb45.selectedJob.get(state.page)||list[list.length-1]?.job.id;wb45.operations.set(state.page,list.filter(x=>x.job.id!==id));saveJobs45();renderOperationResult();},
  'result-select':async b=>{const list=wb45.operations.get(state.page)||[];const op=list.find(x=>String(x.job.id)===b.dataset.id);if(op){wb45.selectedJob.set(state.page,op.job.id);renderOperationResult();}},
  'job-detail':async b=>{const j=await api('/jobs/'+b.dataset.id);selectOperation45(state.page,{page:state.page,label:j.operation,job:j});renderOperationResult();if(!terminalJobStates.has(j.status))watchJob(j.id,state.page,j.operation);}
});
actions['job-result']=actions['job-detail'];
const originalGo45=go;
go=async function(p){
  const same=state.page===p,scroll=window.scrollY;
  if(same && document.activeElement?.matches('input,textarea,select') && !state.busy)return;
  if(!same)wb45.pageScroll.set(state.page,scroll);
  await originalGo45(p);
  if(state.page!==p)return;
  if(location.hash.slice(1)!==p)history.replaceState(null,'','#'+p);
  $('#subtitle').textContent='D\u00f9ng chung b\u1ed9 x\u1eed l\u00fd Desktop \u00b7 K\u1ebft qu\u1ea3 t\u1ea1i ch\u1ed7 \u00b7 D\u1eef li\u1ec7u c\u00f3 th\u1eddi gian \u0111o';
  $('#live-toggle').textContent='L\u00e0m m\u1edbi: '+(state.live?'B\u1eacT':'T\u1eaeT');
  window.scrollTo(0,same?scroll:(wb45.pageScroll.get(p)||0));
};
if(location.hash && (pages[location.hash.slice(1)]||['pingmonitor','managed'].includes(location.hash.slice(1))))state.page=location.hash.slice(1);
window.addEventListener('hashchange',()=>{const p=location.hash.slice(1);if(pages[p]&&state.user&&p!==state.page)go(p);});
const oldLogged45=loggedIn;
loggedIn=async()=>{await oldLogged45();try{const pending=JSON.parse(sessionStorage.getItem('na45_jobs_'+state.user.id)||'[]');for(const item of pending)if(Number.isInteger(item.id)&&pages[item.page])watchJob(item.id,item.page,item.label);}catch{}};

/* Ping monitor, independent of the all-in-one Auto IP workflow. */
tr.pingmonitor='Gi\u00e1m s\u00e1t Ping';tr.managed='Thi\u1ebft b\u1ecb qu\u1ea3n tr\u1ecb';tr.autoip='Auto IP / Automation';
groups[2][1].unshift('pingmonitor');groups[1][1].splice(1,0,'managed');navIcon.pingmonitor='\u2301';navIcon.managed='\u25a3';
function check45(name,label,checked=false){return `<label class="check-field"><input type="checkbox" name="${esc(name)}" ${checked?'checked':''}>${esc(label)}</label>`;}
function targetText45(text){const rows=[];for(const line of text.split(/[\n;]+/)){const parts=line.trim().split(/[,\t]+/);if(!parts[0])continue;if(parts.length===1&&/\s/.test(parts[0])){for(const ip of parts[0].split(/\s+/))rows.push({ip,name:'',profile:''});}else rows.push({ip:parts[0].trim(),name:(parts[1]||'').trim(),profile:(parts[2]||'').trim()});}return rows;}
function pingStatus45(d){const s=d.state;return `<div class="result-header">${badge(s.status)}<b>${s.done||0}/${s.total||0}</b><span>Chu k\u1ef3 ${s.cycle||0}</span></div><div class="progress-line"><progress value="${s.done||0}" max="${s.total||1}"></progress><span>${s.next_run_at?'L\u01b0\u1ee3t ti\u1ebfp: '+esc(new Date(s.next_run_at).toLocaleTimeString()):esc(s.message||'')}</span></div><div class="cards">${metric('C\u00f3 ph\u1ea3n h\u1ed3i',d.summary.Online,'green')}${metric('Kh\u00f4ng ph\u1ea3n h\u1ed3i',d.summary.Offline,'amber')}${metric('Ch\u01b0a \u0111o',d.summary.Unknown)}${metric('L\u1ed7i th\u1ef1c thi',d.summary.Error,'red')}</div>`;}
function pingRows45(d){return grid45(d.targets,[['IP','ip'],['T\u00ean','name'],['ICMP','status',badge],['RTT (ms)','response'],['M\u1ea5t g\u00f3i (%)','packet_loss'],['Th\u1eddi gian \u0111o','observed_at'],['D\u1eef li\u1ec7u','data_state',badge],['Di\u1ec5n gi\u1ea3i','error']],canWrite()&&!d.state.running?r=>button('S\u1eeda','ping-target-edit',{ip:r.ip})+button('X\u00f3a','ping-target-delete',{ip:r.ip},'danger'):null,'ping-target-grid');}
pages.pingmonitor=async()=>{
  const d=await api('/v45/ping');wb45.ping=d;const o=d.state.options||{};
  return panel('Gi\u00e1m s\u00e1t ICMP',`<div id="ping-live-status">${pingStatus45(d)}</div><p class="caption">Ch\u1ea1y tr\u00ean m\u00e1y c\u00e0i Web, kh\u00f4ng ph\u1ea3i m\u00e1y m\u1edf tr\u00ecnh duy\u1ec7t. Kh\u00f4ng ph\u1ea3n h\u1ed3i ping ch\u01b0a \u0111\u1ee7 k\u1ebft lu\u1eadn thi\u1ebft b\u1ecb t\u1eaft.</p>`+(canWrite()?form('ping-run-form',input('Chu k\u1ef3 (gi\u00e2y, t\u1ed1i thi\u1ec3u 5)','interval','number',o.interval||15)+input('Timeout (ms)','timeout_ms','number',o.timeout_ms||1000)+input('S\u1ed1 lu\u1ed3ng (1\u201332)','workers','number',o.workers||16)+check45('repeat','L\u1eb7p l\u1ea1i \u0111\u1ecbnh k\u1ef3',o.repeat),'B\u1eaft \u0111\u1ea7u Ping')+`<div class="toolbar">${button('D\u1eebng Ping','ping-stop',{},'danger')}</div>`:''))+
  panel('Danh s\u00e1ch Ping',`<div class="toolbar">${canWrite()?button('Th\u00eam / d\u00e1n IP','ping-target-add',{},'primary')+button('L\u1ea5y t\u1eeb thi\u1ebft b\u1ecb','ping-import-inventory')+button('Nh\u1eadp file','ping-import-file')+button('X\u00f3a to\u00e0n b\u1ed9 danh s\u00e1ch','ping-clear',{},'danger'):''}</div><p class="caption">X\u00f3a danh s\u00e1ch Ping kh\u00f4ng x\u00f3a thi\u1ebft b\u1ecb, credential hay l\u1ecbch s\u1eed. Danh s\u00e1ch \u0111\u00e3 x\u00f3a kh\u00f4ng t\u1ef1 xu\u1ea5t hi\u1ec7n l\u1ea1i.</p><div id="ping-targets-host">${pingRows45(d)}</div>`);
};
Object.assign(forms,{
  'ping-run-form':async f=>{const v=vals(f);if(!confirm('B\u1ea1n c\u00f3 quy\u1ec1n ki\u1ec3m tra c\u00e1c IP trong danh s\u00e1ch n\u00e0y?'))return;await api('/v45/ping/start',{method:'POST',body:JSON.stringify({authorized:true,repeat:new FormData(f).has('repeat'),interval:Number(v.interval),timeout_ms:Number(v.timeout_ms),workers:Number(v.workers)})});await refreshPing45();},
  'ping-target-form':async f=>{const v=vals(f),targets=targetText45(v.targets);if(!targets.length)throw new Error('Nh\u1eadp \u00edt nh\u1ea5t m\u1ed9t IP.');await api('/v45/ping/targets',{method:'PUT',body:JSON.stringify({targets,mode:'append'})});$('#dialog').close();await go('pingmonitor');},
  'ping-edit-form':async f=>{const v=vals(f);await api('/v45/ping/targets',{method:'PUT',body:JSON.stringify({targets:[{ip:v.ip,name:v.name,profile:''}],mode:'append'})});$('#dialog').close();await go('pingmonitor');}
});
Object.assign(actions,{
  'ping-stop':async()=>{await api('/v45/ping/stop',{method:'POST',body:'{}'});await refreshPing45();},
  'ping-target-add':async()=>modal('Th\u00eam IP v\u00e0o Ping',form('ping-target-form','<label class="wide-field">M\u1ed7i d\u00f2ng: IP ho\u1eb7c IP,T\u00ean<textarea name="targets" rows="8" required placeholder="192.168.1.1,Router"></textarea></label>','L\u01b0u danh s\u00e1ch')),
  'ping-target-edit':async b=>{const t=wb45.ping.targets.find(x=>x.ip===b.dataset.ip);if(t)modal('S\u1eeda t\u00ean IP',form('ping-edit-form',`<input type="hidden" name="ip" value="${esc(t.ip)}">`+input('T\u00ean','name','text',t.name,false),'L\u01b0u'));},
  'ping-target-delete':async b=>{if(confirm('X\u00f3a '+b.dataset.ip+' kh\u1ecfi danh s\u00e1ch Ping?')){await api('/v45/ping/targets/'+encodeURIComponent(b.dataset.ip),{method:'DELETE'});await go('pingmonitor');}},
  'ping-clear':async()=>{if(prompt('Nh\u1eadp DELETE \u0111\u1ec3 x\u00f3a danh s\u00e1ch Ping. Thi\u1ebft b\u1ecb v\u1eabn \u0111\u01b0\u1ee3c gi\u1eef nguy\u00ean.')!=='DELETE')return;await api('/v45/ping/targets',{method:'PUT',body:JSON.stringify({targets:[],mode:'replace',confirmation:'REPLACE'})});await go('pingmonitor');},
  'ping-import-inventory':async()=>{await api('/v45/ping/import-inventory',{method:'POST',body:'{}'});await go('pingmonitor');},
  'ping-import-file':async()=>importModal45('ping')
});
async function refreshPing45(){if(state.page!=='pingmonitor')return;const generation=state.render;const d=await api('/v45/ping');if(state.page!=='pingmonitor'||generation!==state.render)return;wb45.ping=d;if($('#ping-live-status'))$('#ping-live-status').innerHTML=pingStatus45(d);if($('#ping-targets-host')&&!document.activeElement?.dataset.gridFilter)window.patchHTML46($('#ping-targets-host'),pingRows45(d));syncRunControls45();}


/* Preserve coordinator state after generic action/submit handlers finish.
   Otherwise their finally blocks re-enable Start while the worker is running. */
function syncRunControls45(){
 const ping=wb45.ping?.state;
 if(state.page==='pingmonitor'&&ping){
  const start=$('#ping-run-form button[type=submit]');if(start)start.disabled=state.busy||!!ping.running;
  const stop=$('[data-action="ping-stop"]');if(stop)stop.disabled=state.busy||!ping.running;
 }
 const auto=wb45.auto?.s;
 if(state.page==='autoip'&&auto){
  const start=$('#auto-options-form button[type=submit]');if(start)start.disabled=state.busy||!!auto.running;
 }
}
window.addEventListener('na46:ready',()=>syncRunControls45());

/* Auto IP is the desktop AutomationEngine with all options exposed. */
const autoBooleans45={ping:'Ping ICMP',tcp:'Ki\u1ec3m tra c\u1ed5ng TCP',snmp:'SNMP / nh\u1eadn di\u1ec7n driver',resources:'CPU / RAM',interfaces:'Interface / l\u01b0u l\u01b0\u1ee3ng',topology:'Topology LLDP/CDP',backup:'Backup c\u1ea5u h\u00ecnh SSH',alerts:'\u0110\u00e1nh gi\u00e1 c\u1ea3nh b\u00e1o',report:'T\u1ea1o b\u00e1o c\u00e1o Excel',notifications:'G\u1eedi th\u00f4ng b\u00e1o',email_report_after_run:'G\u1eedi b\u00e1o c\u00e1o qua email'};
function autoForm45(o,profiles){return `<form id="auto-options-form"><div class="task-checks">${Object.entries(autoBooleans45).map(([k,v])=>check45(k,v,o[k])).join('')}</div><div class="form-grid">${select('Profile m\u1eb7c \u0111\u1ecbnh','default_profile',profiles.map(p=>p.name),o.default_profile)}${input('Workers (1\u201316)','workers','number',o.workers)}${input('Timeout (gi\u00e2y)','timeout','number',o.timeout)}${input('Chu k\u1ef3 (gi\u00e2y, >=30)','interval','number',o.interval)}${check45('repeat','L\u1eb7p theo chu k\u1ef3',o.repeat)}</div><details><summary>T\u00f9y ch\u1ecdn n\u00e2ng cao</summary><div class="form-grid">${input('Retry (0\u20132)','retries','number',o.retries)}${input('Gi\u1edbi h\u1ea1n interface','max_interfaces','number',o.max_interfaces)}${input('Ng\u00e2n s\u00e1ch m\u1ed7i IP (gi\u00e2y)','device_budget','number',o.device_budget)}${input('C\u1ed5ng TCP','ports','text',o.ports)}${input('Email nh\u1eadn b\u00e1o c\u00e1o','report_email_to','email',o.report_email_to||'',false)}</div></details><div class="toolbar toolbar-gap"><button class="primary" type="submit">Ch\u1ea1y Auto IP</button>${isAdmin()?button('L\u01b0u t\u00f9y ch\u1ecdn','auto-save-options'):''}${button('D\u1eebng','auto-stop45',{},'danger')}</div></form>`;}
function readAutoOptions45(f){const v=vals(f),fd=new FormData(f);const o={default_profile:v.default_profile,ports:v.ports,report_email_to:v.report_email_to||'',repeat:fd.has('repeat'),auto_start:false};for(const k of Object.keys(autoBooleans45))o[k]=fd.has(k);for(const k of ['workers','timeout','interval','retries','max_interfaces','device_budget'])o[k]=Number(v[k]);return o;}
function autoStatus45(s){return `<div class="result-header">${badge(s.status)}<b>${s.done||0}/${s.total||0} IP</b><span>Chu k\u1ef3 ${s.cycle||0}</span></div><div class="progress-line"><progress value="${s.done||0}" max="${s.total||1}"></progress><span>${esc(s.message||'')}</span></div>${!s.enabled?'<div class="error">Auto IP ch\u01b0a b\u1eadt. D\u1eebng Web c\u0169 v\u00e0 ch\u1ea1y START_WEB.bat c\u1ee7a b\u1ea3n n\u00e0y.</div>':''}`;}
pages.autoip=async()=>{
 const [targets,history,s,options,profiles]=await Promise.all([api('/autoip/targets?limit=2048'),api('/autoip/history'),api('/autoip/status'),api('/autoip/options'),api('/autoip/profiles')]);
 wb45.auto={targets,history,s,options,profiles};
 if(wb45.followAuto&&s.run_id&&wb45.activeRun!==s.run_id){wb45.activeRun=s.run_id;wb45.autoSteps=[];}
 return panel('B\u1ed9 x\u1eed l\u00fd Auto IP',`<div id="auto-live-status">${autoStatus45(s)}</div><div class="inline-notice">C\u00f9ng b\u1ed9 x\u1eed l\u00fd v\u1edbi app. B\u01b0\u1edbc thi\u1ebfu credential / driver s\u1ebd hi\u1ec7n SKIP ho\u1eb7c ERROR, kh\u00f4ng coi l\u00e0 ki\u1ec3m tra th\u00e0nh c\u00f4ng.</div>`+(canWrite()?autoForm45(options,profiles):''))+
 panel('Danh s\u00e1ch IP \u0111\u01b0\u1ee3c ph\u00e9p ch\u1ea1y',`<div class="toolbar">${isAdmin()?button('Th\u00eam / d\u00e1n IP','auto-target-add',{},'primary')+button('Nh\u1eadp Excel / CSV / TXT','auto-import45')+button('H\u1ed3 s\u01a1 k\u1ebft n\u1ed1i','auto-profiles45')+button('X\u00f3a danh s\u00e1ch','auto-clear45',{},'danger'):''}</div>`+grid45(targets,[['IP','ip'],['T\u00ean','name'],['Profile','profile']],isAdmin()?r=>button('S\u1eeda','auto-target-edit',{ip:r.ip})+button('X\u00f3a','auto-target-delete',{ip:r.ip},'danger'):null,'auto-target-grid'))+
 panel('K\u1ebft qu\u1ea3 t\u1eebng b\u01b0\u1edbc',`<div id="auto-run-output">${wb45.activeRun?'<p class="muted">\u0110ang t\u1ea3i k\u1ebft qu\u1ea3...</p>':empty('Ch\u01b0a c\u00f3 l\u01b0\u1ee3t ch\u1ea1y. Nh\u1ea5n Ch\u1ea1y Auto IP ho\u1eb7c ch\u1ecdn l\u1ecbch s\u1eed b\u00ean d\u01b0\u1edbi.')}</div>`)+
 panel('L\u1ecbch s\u1eed Auto IP',table(history,[['Th\u1eddi gian','started_at'],['Tr\u1ea1ng th\u00e1i','status',badge],['IP','total'],['Chu k\u1ef3','cycle'],['Ng\u01b0\u1eddi ch\u1ea1y','username']],r=>button('Xem k\u1ebft qu\u1ea3','auto-run-view',{id:r.id})+button('T\u1ea3i Excel','auto-run-report',{id:r.id})));
};
function autoTargetModal45(t={}){const profiles=wb45.auto.profiles;modal('IP / Profile',form('auto-target-edit-form',(t.ip?`<label>IP<input name="ip" value="${esc(t.ip)}" readonly></label>`:input('IP','ip'))+input('T\u00ean','name','text',t.name||'',false)+select('Profile','profile',[['','D\u00f9ng m\u1eb7c \u0111\u1ecbnh'],...profiles.map(p=>[p.name,p.name])],t.profile||''),'L\u01b0u'));}
Object.assign(forms,{
 'auto-options-form':async f=>{const o=readAutoOptions45(f);if(!confirm('Ch\u1ea1y c\u00e1c b\u01b0\u1edbc \u0111\u00e3 ch\u1ecdn tr\u00ean danh s\u00e1ch IP thu\u1ed9c quy\u1ec1n qu\u1ea3n tr\u1ecb c\u1ee7a b\u1ea1n?'))return;const notify=o.notifications||o.email_report_after_run;if(notify&&!confirm('X\u00e1c nh\u1eadn g\u1eedi th\u00f4ng b\u00e1o / email th\u1eadt \u0111\u1ebfn k\u00eanh \u0111\u00e3 c\u1ea5u h\u00ecnh?'))return;await api('/v45/autoip/start',{method:'POST',body:JSON.stringify({authorized:true,options:o,confirm_notifications:!!notify})});wb45.followAuto=true;wb45.activeRun='';wb45.autoSteps=[];await refreshAuto45();},
 'auto-target-edit-form':async f=>{const v=vals(f);await api('/v45/autoip/targets',{method:'PUT',body:JSON.stringify({targets:[v],mode:'append'})});$('#dialog').close();await go('autoip');},
 'auto-target-paste-form':async f=>{const targets=targetText45(vals(f).targets);if(!targets.length)throw new Error('Danh s\u00e1ch IP tr\u1ed1ng.');await api('/v45/autoip/targets',{method:'PUT',body:JSON.stringify({targets,mode:'append'})});$('#dialog').close();await go('autoip');}
});
Object.assign(actions,{
 'auto-save-options':async()=>{const f=$('#auto-options-form');if(!f.reportValidity())return;await api('/v45/autoip/options',{method:'PUT',body:JSON.stringify(readAutoOptions45(f))});window.naRefresh46?.clean(f);toast('\u0110\u00e3 l\u01b0u t\u00f9y ch\u1ecdn.');},
 'auto-stop45':async()=>{await api('/v45/autoip/stop',{method:'POST',body:'{}'});await refreshAuto45();},
 'auto-target-add':async()=>modal('D\u00e1n danh s\u00e1ch IP',form('auto-target-paste-form','<label class="wide-field">M\u1ed7i d\u00f2ng: IP,T\u00ean,Profile (t\u00ean / profile c\u00f3 th\u1ec3 \u0111\u1ec3 tr\u1ed1ng)<textarea name="targets" required rows="8" placeholder="192.168.1.1,Router,"></textarea></label>','Th\u00eam danh s\u00e1ch')),
 'auto-target-edit':async b=>autoTargetModal45(wb45.auto.targets.find(x=>x.ip===b.dataset.ip)),
 'auto-target-delete':async b=>{if(confirm('X\u00f3a '+b.dataset.ip+' kh\u1ecfi Auto IP?')){await api('/v45/autoip/targets/'+encodeURIComponent(b.dataset.ip),{method:'DELETE'});await go('autoip');}},
 'auto-clear45':async()=>{if(prompt('Nh\u1eadp DELETE \u0111\u1ec3 x\u00f3a danh s\u00e1ch Auto IP, kh\u00f4ng x\u00f3a thi\u1ebft b\u1ecb / credential.')!=='DELETE')return;await api('/v45/autoip/targets',{method:'PUT',body:JSON.stringify({targets:[],mode:'replace',confirmation:'REPLACE'})});await go('autoip');},
 'auto-run-view':async b=>{wb45.followAuto=false;wb45.activeRun=b.dataset.id;wb45.autoSteps=[];await refreshAuto45();$('#auto-run-output')?.scrollIntoView({behavior:'smooth',block:'start'});},
 'auto-run-report':async b=>{const r=await api('/v45/autoip/runs/'+encodeURIComponent(b.dataset.id)+'/report',{method:'POST',body:'{}'});immediate45(r,'B\u00e1o c\u00e1o Auto IP');},
 'auto-import45':async()=>importModal45('autoip'),
 'auto-profiles45':async()=>{const [profiles,creds,v3]=await Promise.all([api('/connection-profiles'),api('/credentials'),api('/snmpv3/credentials')]);wb45.connectionProfiles=profiles;modal('H\u1ed3 s\u01a1 k\u1ebft n\u1ed1i Auto IP',table(profiles,[['T\u00ean','name'],['Ch\u1ebf \u0111\u1ed9','mode'],['Port','port'],['C\u00f3 community','has_community']])+form('connection45-form',input('T\u00ean (tr\u00f9ng t\u00ean = c\u1eadp nh\u1eadt)','name')+select('SNMP','mode',[['assigned','D\u00f9ng credential \u0111\u00e3 g\u00e1n'],['off','T\u1eaft SNMP'],['v2c','SNMPv2c'],['v3','SNMPv3']])+input('Community (\u0111\u1ec3 tr\u1ed1ng gi\u1eef nguy\u00ean)','community','password','',false)+select('SNMPv3','snmpv3_id',[['','Kh\u00f4ng ch\u1ecdn'],...v3.map(x=>[x.id,x.name])])+select('SSH','ssh_id',[['','Theo thi\u1ebft b\u1ecb'],...creds.map(x=>[x.id,x.name])])+input('SNMP port','port','number',161),'L\u01b0u profile'));}
});
forms['connection45-form']=async f=>{const v=vals(f);for(const k of ['snmpv3_id','ssh_id'])v[k]=v[k]?Number(v[k]):null;v.port=Number(v.port);await api('/connection-profiles',{method:'POST',body:JSON.stringify(v)});$('#dialog').close();await go('autoip');};
async function refreshAuto45(){
 if(state.page!=='autoip')return;
 const s=await api('/autoip/status');if(state.page!=='autoip')return;if(wb45.auto)wb45.auto.s=s;if($('#auto-live-status'))$('#auto-live-status').innerHTML=autoStatus45(s);
 const b=$('#auto-options-form button[type=submit]');if(b)b.disabled=s.running||!s.enabled;
 if(wb45.followAuto&&s.run_id&&wb45.activeRun!==s.run_id){wb45.activeRun=s.run_id;wb45.autoSteps=[];}
 if(!wb45.activeRun||!$('#auto-run-output'))return;
 const last=wb45.autoSteps.length?wb45.autoSteps[wb45.autoSteps.length-1].id:0;
 const generation=state.render;const r=await api('/v45/autoip/runs/'+encodeURIComponent(wb45.activeRun)+'?after='+last+'&limit=2000');if(state.page!=='autoip'||generation!==state.render)return;
 if(r.run.id!==wb45.activeRun)return;
 const seen=new Set(wb45.autoSteps.map(x=>x.id));wb45.autoSteps.push(...r.steps.filter(x=>!seen.has(x.id)));
 const host=$('#auto-run-output');if(!host)return;
 if(!document.activeElement?.dataset.gridFilter&&!host.querySelector('.cell-detail[open]'))window.patchHTML46(host,`<div class="result-header"><b>${esc(r.run.started_at)}</b>${badge(r.run.status)}${button('T\u1ea3i b\u00e1o c\u00e1o Excel','auto-run-report',{id:r.run.id})}</div><div class="cards">${Object.entries(r.summary).map(([k,v])=>metric(k,v,k==='OK'?'green':k==='ERROR'?'red':'amber')).join('')}</div>`+grid45(wb45.autoSteps,[['IP','ip'],['B\u01b0\u1edbc','task'],['K\u1ebft qu\u1ea3','status',badge],['Di\u1ec5n gi\u1ea3i','message'],['S\u1ed1 li\u1ec7u','data',(v)=>scalar45(v)],['Th\u1eddi gian','created_at']],null,'auto-steps-grid'));
}

/* File imports are parsed by the existing desktop parser; credentials are never in files. */
function importModal45(kind){modal('Nh\u1eadp danh s\u00e1ch IP',form('file-import45-form',`<input type="hidden" name="kind" value="${kind}"><label class="wide-field">File .xlsx / .csv / .txt<input name="upload" type="file" accept=".xlsx,.csv,.txt" required></label><p class="caption wide-field">Excel/CSV: c\u1ed9t IP, Name, Profile. TXT: danh s\u00e1ch IP. T\u1ed1i \u0111a 2048 IP, file 8 MB. Ch\u1ec9 th\u00eam, kh\u00f4ng ghi \u0111\u00e8 thi\u1ebft b\u1ecb hi\u1ec7n c\u00f3.</p>`,'Nh\u1eadp file'));}

function ipmacImportModal45(){modal('Thêm thiết bị bằng file',form('ipmac-file-import45-form',`<label class="wide-field">File .xlsx / .csv / .txt<input name="upload" type="file" accept=".xlsx,.csv,.txt" required></label><div class="inline-notice wide-field"><b>Cột hỗ trợ:</b> IP (bắt buộc), MAC, Hostname/Tên thiết bị, Note/Ghi chú.</div><p class="caption wide-field">Tối đa 5000 dòng, file 8 MB. Chỉ thêm IP mới; IP đã tồn tại sẽ được bỏ qua để không ghi đè dữ liệu hiện có.</p><p class="caption wide-field"><a class="button-link" href="/static/IPMAC_Mau.csv" download>Tải file mẫu IP/MAC</a></p>`,'Nhập thiết bị'));}
forms['ipmac-file-import45-form']=async f=>{const file=f.elements.upload.files[0];if(!file)throw new Error('Chọn file.');if(file.size>8*1024*1024)throw new Error('File vượt 8 MB.');const bytes=new Uint8Array(await file.arrayBuffer());let bin='';for(let i=0;i<bytes.length;i+=32768)bin+=String.fromCharCode(...bytes.subarray(i,i+32768));const r=await api('/v45/ipmac/import-file',{method:'POST',body:JSON.stringify({filename:file.name,content_base64:btoa(bin),mode:'append'})});$('#dialog').close();await go('ipmac');immediate45(r,`Đã thêm ${r.created||0} thiết bị · bỏ qua ${r.existing||0} IP đã có · trùng trong file ${r.duplicates_skipped||0}`);};
forms['file-import45-form']=async f=>{const file=f.elements.upload.files[0];if(!file)throw new Error('Ch\u1ecdn file.');if(file.size>8*1024*1024)throw new Error('File v\u01b0\u1ee3t 8 MB.');const bytes=new Uint8Array(await file.arrayBuffer());let bin='';for(let i=0;i<bytes.length;i+=32768)bin+=String.fromCharCode(...bytes.subarray(i,i+32768));const kind=f.elements.kind.value,path=kind==='inventory'?'/v45/inventory/import':'/v45/'+kind+'/import';const r=await api(path,{method:'POST',body:JSON.stringify({filename:file.name,content_base64:btoa(bin),mode:'append'})});$('#dialog').close();await go(kind==='inventory'?'devices':kind==='ping'?'pingmonitor':'autoip');immediate45(r,'Nh\u1eadp danh s\u00e1ch IP');};

/* Missing inventory / IP-MAC workflows. */
const oldDevices45=pages.devices;
pages.devices=async()=>{const html=await oldDevices45();return `<div class="toolbar">${canWrite()?button('Ping to\u00e0n b\u1ed9','job',{op:'PING_ALL'})+button('M\u1edf gi\u00e1m s\u00e1t Ping','page',{page:'pingmonitor'}):''}${isAdmin()?button('Nh\u1eadp IP t\u1eeb file','inventory-import45'):''}</div>`+html;};
actions['inventory-import45']=async()=>importModal45('inventory');
pages.managed=async()=>{state.managed=await api('/managed-devices');return panel('Thi\u1ebft b\u1ecb qu\u1ea3n tr\u1ecb',`<p class="caption">ID qu\u1ea3n tr\u1ecb d\u00f9ng cho SSH, SNMP, Backup. Th\u00eam IP t\u1ea1i Thi\u1ebft b\u1ecb r\u1ed3i ch\u1ecdn Enable managed tasks.</p>`+table(state.managed,[['ID','id'],['IP','ip'],['T\u00ean','name'],['Vendor','vendor'],['Lo\u1ea1i','device_type'],['V\u1ecb tr\u00ed','location'],['C\u1eadp nh\u1eadt','updated_at']],r=>(isAdmin()?button('S\u1eeda','managed-edit45',{id:r.id})+button('C\u1ea5u h\u00ecnh k\u1ebft n\u1ed1i','device-setup',{id:r.id}):'')+(canWrite()?button('SNMP','job',{op:'SNMP',id:r.id})+button('SSH','job',{op:'SSH_TEST',id:r.id}):'')));};
actions['managed-edit45']=async b=>{const r=state.managed.find(x=>x.id===Number(b.dataset.id));if(r)modal('Thi\u1ebft b\u1ecb '+r.ip,form('managed-edit45-form',`<input name="id" type="hidden" value="${r.id}">`+input('T\u00ean','name','text',r.name)+input('Vendor','vendor','text',r.vendor||'',false)+input('Lo\u1ea1i','device_type','text',r.device_type||'',false)+input('V\u1ecb tr\u00ed','location','text',r.location||'',false),'L\u01b0u'));};
forms['managed-edit45-form']=async f=>{const v=vals(f),id=v.id;delete v.id;await api('/v45/managed/'+id,{method:'PUT',body:JSON.stringify(v)});$('#dialog').close();await go('managed');};
pages.ipmac=async()=>{
  wb45.ipmac=await api('/v45/ipmac');
  wb45.ipmacSelected=wb45.ipmacSelected||new Set();
  const valid=new Set(wb45.ipmac.map(r=>Number(r.id)));
  for(const id of [...wb45.ipmacSelected])if(!valid.has(id))wb45.ipmacSelected.delete(id);
  const age=v=>{if(v===null||v===undefined)return '<span class="muted">Chưa có phép đo</span>';if(v<60)return esc(v+' giây trước');if(v<3600)return esc(Math.floor(v/60)+' phút trước');if(v<86400)return esc(Math.floor(v/3600)+' giờ trước');return esc(Math.floor(v/86400)+' ngày trước');};
  const select=(v,r)=>`<input type="checkbox" data-ipmac-select="${Number(r.id)}" ${wb45.ipmacSelected.has(Number(r.id))?'checked':''} aria-label="Chọn ${esc(r.ip)}">`;
  const controls=canWrite()?`<div class="toolbar ipmac-bulk">${button('Chọn các dòng đang lọc','ipmac-select-filtered45')}${button('Bỏ chọn','ipmac-clear-selection45')}<span id="ipmac-selected-count" class="muted">Đã chọn ${wb45.ipmacSelected.size}</span>${button('Xóa đã chọn','ipmac-delete-selected45',{},'danger')}${button('Xóa theo bộ lọc','ipmac-delete-filtered45',{},'danger')}${isAdmin()?button('Xóa toàn bộ','ipmac-delete-all45',{},'danger'):''}</div>`:'';
  const notice=`<div class="inline-notice"><b>IP/MAC là dữ liệu inventory lịch sử.</b> Online của lượt quét cũ không được coi là trạng thái hiện tại. Bản ghi quá 3 phút không có quan sát mới sẽ hiển thị <b>STALE</b>. Dùng “Quét mạng” để cập nhật.</div>`;
  return panel('Quản lý IP / MAC',`<div class="toolbar">${canWrite()?button('Thêm bản ghi','ipmac-add45',{},'primary')+button('Thêm thiết bị bằng file','ipmac-import-file45'):''}${(window.naBrowserOnlyMode?.()===true)?'':(canWrite()?button('Quét thiết bị đang kết nối','startup-scan-force5010',{},'primary'):'')}${isAdmin()?button(window.naBrowserOnlyMode?.()===true?'Giới hạn quét LAN trên Web':'Quét mạng','page',{page:'scan'})+((window.naBrowserOnlyMode?.()===true)?'':button('Lấy kết quả quét gần nhất','ipmac-scan-import45')):''}</div><div id="connected-devices623" class="inline-notice"><b>Thiết bị đang kết nối:</b> đang tải dữ liệu quét LAN gần nhất...</div>`+notice+controls+grid45(wb45.ipmac,[['Chọn','id',select],['IP','ip'],['MAC','mac'],['Tên','hostname'],['Xung đột','conflict'],['Ghi chú','note'],['Trạng thái hiển thị','effective_status',badge],['Kết quả lần quét','observed_status',v=>`<span class="muted">${esc(v||'Unknown')}</span>`],['Độ mới','age_seconds',age],['Lần cuối','last_seen']],canWrite()?r=>button('Sửa','ipmac-edit45',{id:r.id})+button('Xóa','ipmac-delete45',{id:r.id},'danger'):null,'ipmac-grid'));
};
function ipmacModal45(r={}){modal('B\u1ea3n ghi IP / MAC',form('ipmac45-form',`<input type="hidden" name="id" value="${r.id||''}">`+input('IP','ip','text',r.ip||'')+input('MAC (AA:BB:CC:DD:EE:FF)','mac','text',r.mac||'',false)+input('Hostname','hostname','text',r.hostname||'',false)+input('Ghi ch\u00fa','note','text',r.note||'',false),'L\u01b0u'));}
Object.assign(actions,{
 'ipmac-add45':async()=>ipmacModal45(),
 'ipmac-import-file45':async()=>ipmacImportModal45(),
 'ipmac-edit45':async b=>ipmacModal45(wb45.ipmac.find(r=>r.id===Number(b.dataset.id))),
 'ipmac-delete45':async b=>{if(confirm('X\u00f3a b\u1ea3n ghi IP/MAC n\u00e0y?')){await api('/v45/ipmac/'+b.dataset.id,{method:'DELETE'});await go('ipmac');}},
 'ipmac-delete-selected45':async()=>{const ids=[...(wb45.ipmacSelected||new Set())];if(!ids.length){toast('Chưa chọn bản ghi nào.',true);return;}if(!confirm(`Xóa ${ids.length} bản ghi IP/MAC đã chọn?`))return;const r=await api('/v45/ipmac/delete-many',{method:'POST',body:JSON.stringify({ids,confirmation:'DELETE_SELECTED'})});wb45.ipmacSelected.clear();await go('ipmac');toast(`Đã xóa ${r.deleted} bản ghi.`);},
 'ipmac-select-filtered45':async()=>{const g=wb45.grids.get('ipmac-grid');if(!g)return;const term=(g.filter||'').toLocaleLowerCase();const rows=g.rows.filter(r=>!term||JSON.stringify(r).toLocaleLowerCase().includes(term));wb45.ipmacSelected=wb45.ipmacSelected||new Set();rows.forEach(r=>wb45.ipmacSelected.add(Number(r.id)));repaintGrid45('ipmac-grid');const c=document.getElementById('ipmac-selected-count');if(c)c.textContent='Đã chọn '+wb45.ipmacSelected.size;},
 'ipmac-clear-selection45':async()=>{wb45.ipmacSelected?.clear();repaintGrid45('ipmac-grid');const c=document.getElementById('ipmac-selected-count');if(c)c.textContent='Đã chọn 0';},
 'ipmac-delete-filtered45':async()=>{const g=wb45.grids.get('ipmac-grid');if(!g)return;const term=(g.filter||'').trim().toLocaleLowerCase();if(!term){toast('Hãy nhập bộ lọc trước. Xóa toàn bộ dùng nút riêng.',true);return;}const ids=g.rows.filter(r=>JSON.stringify(r).toLocaleLowerCase().includes(term)).map(r=>Number(r.id));if(!ids.length){toast('Bộ lọc không có bản ghi.',true);return;}if(!confirm(`Xóa ${ids.length} bản ghi phù hợp bộ lọc “${g.filter}”?`))return;const r=await api('/v45/ipmac/delete-many',{method:'POST',body:JSON.stringify({ids,confirmation:'DELETE_SELECTED'})});ids.forEach(id=>wb45.ipmacSelected?.delete(id));await go('ipmac');toast(`Đã xóa ${r.deleted} bản ghi theo bộ lọc.`);},
 'ipmac-delete-all45':async()=>{const typed=prompt('Xóa TOÀN BỘ IP/MAC inventory? Thao tác không xóa thiết bị/credential.\\nGõ: XOA TAT CA');if(typed!=='XOA TAT CA'){if(typed!==null)toast('Đã hủy: chuỗi xác nhận không đúng.',true);return;}const r=await api('/v45/ipmac/delete-all',{method:'POST',body:JSON.stringify({confirmation:'DELETE_ALL_IPMAC'})});wb45.ipmacSelected?.clear();await go('ipmac');toast(`Đã xóa toàn bộ ${r.deleted} bản ghi IP/MAC.`);},
 'ipmac-scan-import45':async()=>{if(confirm('Nh\u1eadp c\u00e1c IP Online t\u1eeb l\u01b0\u1ee3t qu\u00e9t g\u1ea7n nh\u1ea5t? Ghi ch\u00fa c\u0169 \u0111\u01b0\u1ee3c gi\u1eef l\u1ea1i.')){const r=await api('/v45/ipmac/import-scan',{method:'POST',body:'{}'});await go('ipmac');immediate45(r,'Nh\u1eadp IP/MAC t\u1eeb k\u1ebft qu\u1ea3 qu\u00e9t');}}
});
forms['ipmac45-form']=async f=>{const v=vals(f),id=v.id;delete v.id;await api('/v45/ipmac'+(id?'/'+id:''),{method:id?'PUT':'POST',body:JSON.stringify(v)});$('#dialog').close();await go('ipmac');};

/* Every potentially slow command goes through the durable worker, not a 20s HTTP call. */
async function task45(operation,device_ids=[],extra={}){const page=state.page;const r=await api('/v45/tasks',{method:'POST',body:JSON.stringify({operation,device_ids,authorized:true,...extra})});$('#dialog').close();trackQueuedJob(r,operation,page);}
actions['monitor-resource']=async b=>{if(confirm('\u0110\u1ecdc CPU/RAM b\u1eb1ng SNMP tr\u00ean thi\u1ebft b\u1ecb n\u00e0y?'))await task45('RESOURCE_POLL',[Number(b.dataset.id)]);};
forms['interface-poll-form']=async f=>{const v=vals(f),ifindices=v.ifindices.split(',').map(x=>Number(x.trim()));if(!ifindices.length||ifindices.some(x=>!Number.isInteger(x)||x<1))throw new Error('IfIndex kh\u00f4ng h\u1ee3p l\u1ec7.');await task45('INTERFACE_POLL',[Number(v.device_id)],{ifindices});};
forms['remote-form']=async f=>{const v=vals(f);await task45('REMOTE_CHECK',[Number(v.device_id)],{service:v.service});};
actions['notify-test']=async b=>{if(confirm('G\u1eedi th\u00f4ng b\u00e1o th\u1eed t\u1edbi k\u00eanh \u0111\u00e3 c\u1ea5u h\u00ecnh?'))await task45('NOTIFICATION_TEST',[],{channel:b.dataset.channel});};
const oldRemote45=pages.remote;
pages.remote=async()=>{const d=await api('/managed-devices');return await oldRemote45()+panel('M\u1edf k\u1ebft n\u1ed1i t\u1eeb m\u00e1y c\u1ee7a b\u1ea1n',table(d,[['IP','ip'],['T\u00ean','name']],r=>canWrite()?`<a class="button-link" href="/api/v45/remote/${r.id}/rdp" download>T\u1ea3i file RDP</a>`:''));};
const oldDaily45=pages.dailyaudit;
pages.dailyaudit=async()=>{let html=await oldDaily45();const cap=await api('/v45/capabilities');if(!cap.daily_audit_available){const t=document.createElement('template');t.innerHTML=html;t.content.querySelector('[data-action=daily-audit-run]')?.setAttribute('disabled','');html=t.innerHTML;}return (!cap.daily_audit_available?'<div class="notice47 warn">Daily Audit c\u1ea7n m\u00e1y ch\u1ea1y Web l\u00e0 Windows. Kh\u00f4ng ch\u1ea1y PowerShell audit tr\u00ean Linux.</div>':'')+html;};

/* Charts use only actual observations. Null values are never turned into zero. */
function chart45(rows,field,title){const samples=rows.filter(r=>r[field]!=null&&Number.isFinite(Number(r[field]))).slice(0,100).reverse();if(!samples.length)return panel(title,empty('Ch\u01b0a c\u00f3 ph\u00e9p \u0111o. Ch\u1ea1y Ping / SNMP \u0111\u1ec3 thu th\u1eadp d\u1eef li\u1ec7u.'));const max=Math.max(1,...samples.map(r=>Number(r[field]))),min=Math.min(0,...samples.map(r=>Number(r[field]))),range=max-min||1;const points=samples.map((r,i)=>`${30+i*640/Math.max(1,samples.length-1)},${150-(Number(r[field])-min)*120/range}`).join(' ');return panel(title,`<div class="real-chart"><svg viewBox="0 0 700 180" role="img" aria-label="${esc(title)}"><path d="M30 20V150H680" class="chart-axis"/><polyline points="${points}" class="chart-line"/>${samples.length===1?`<circle cx="30" cy="${150-(Number(samples[0][field])-min)*120/range}" r="4" class="chart-point"/>`:''}<text x="32" y="17">${max.toFixed(1)}</text><text x="32" y="175">${esc(samples[0].created_at||samples[0].observed_at||samples[0].ping_time||'')}</text></svg></div><p class="caption">${samples.length} ph\u00e9p \u0111o \u00b7 M\u1edbi nh\u1ea5t: ${esc(samples[samples.length-1][field])}</p>`);}
const oldHealth45=pages.health;
pages.health=async()=>{const devices=await api('/devices');state.healthDevice=state.healthDevice||devices[0]?.id;let samples=[];if(state.healthDevice){const r=await api('/devices/'+state.healthDevice+'/detail');samples=r.health||[];}return panel('Bi\u1ec3u \u0111\u1ed3 d\u1eef li\u1ec7u th\u1eadt',form('health-select45-form',select('Thi\u1ebft b\u1ecb','device_id',devices.map(d=>[d.id,d.ip+' '+(d.hostname||'')]),state.healthDevice),'Xem'))+`<div class="grid2">${chart45(samples,'cpu','CPU (%)')}${chart45(samples,'memory','RAM (%)')}${chart45(samples,'latency_ms','\u0110\u1ed9 tr\u1ec5 (ms)')}${chart45(samples,'packet_loss','M\u1ea5t g\u00f3i (%)')}</div>`+await oldHealth45();};
forms['health-select45-form']=async f=>{state.healthDevice=Number(vals(f).device_id);await go('health');};
const oldDashboard45=pages.dashboard;
pages.dashboard=async()=>{const cap=await api('/v45/capabilities');const missing=Object.entries(cap.libraries).filter(([,v])=>!v).map(([k])=>k);return `<div class="workbench-banner"><div><small>OPERATIONS CENTER</small><h2>Gi\u00e1m s\u00e1t v\u00e0 v\u1eadn h\u00e0nh</h2><p>Ch\u1ecdn ch\u1ee9c n\u0103ng, ch\u1ea1y v\u00e0 xem k\u1ebft qu\u1ea3 ngay t\u1ea1i trang.</p></div><div class="toolbar">${button('Gi\u00e1m s\u00e1t Ping','page',{page:'pingmonitor'},'primary')}${canWrite()?button('Auto IP','page',{page:'autoip'}):''}${isAdmin()?button('C\u1ea5u h\u00ecnh k\u1ebft n\u1ed1i','page',{page:'credentials'}):''}</div></div>${missing.length?`<div class="error">M\u00e1y ch\u1ea1y Web \u0111ang thi\u1ebfu th\u01b0 vi\u1ec7n: ${esc(missing.join(', '))}. Ch\u1ea1y INSTALL_WEB.bat \u0111\u1ec3 c\u00e0i; c\u00e1c t\u00e1c v\u1ee5 ph\u1ee5 thu\u1ed9c ch\u01b0a s\u1eb5n s\u00e0ng.</div>`:''}${!cap.ping_available?'<div class="error">M\u00e1y ch\u1ea1y Web ch\u01b0a c\u00f3 l\u1ec7nh ping.</div>':''}`+await oldDashboard45();};

/* Enterprise Security actions use the same defensive desktop functions. */
const oldSecurity45=pages.security;
pages.security=async()=>{const html=await oldSecurity45();const assets=await api('/security/assets?limit=2000');return panel('Thao t\u00e1c b\u1ea3o m\u1eadt',`<div class="toolbar">${isAdmin()?button('\u0110\u1ed3ng b\u1ed9 t\u00e0i s\u1ea3n','security-sync45'):''}</div><p class="caption">TCP ch\u1ec9 x\u00e1c \u0111\u1ecbnh c\u1ed5ng m\u1edf. TLS \u0111\u1ecdc handshake/fingerprint, kh\u00f4ng ch\u1ee9ng nh\u1eadn \u0111\u1ed9 tin c\u1eady certificate.</p>`+table(assets,[['IP','ip'],['Hostname baseline','expected_hostname'],['MAC baseline','expected_mac'],['Identity','identity_status',badge]],r=>canWrite()?button('TCP Check','security-task45',{op:'SECURITY_TCP',id:r.id})+button('TLS Check','security-task45',{op:'SECURITY_TLS',id:r.id})+button('X\u00e1c minh Identity','security-identity45',{id:r.id,ip:r.ip}):''))+html+panel('X\u1eed l\u00fd s\u1ef1 ki\u1ec7n',table(await api('/security/events?limit=500'),[['IP','asset_ip'],['S\u1ef1 ki\u1ec7n','title'],['Tr\u1ea1ng th\u00e1i','status',badge]],r=>canWrite()&&r.status==='OPEN'?button('\u0110\u00f3ng','security-close45',{id:r.id}):''));};
Object.assign(actions,{
 'security-sync45':async()=>{const r=await api('/v45/security/sync',{method:'POST',body:'{}'});await go('security');immediate45(r,'\u0110\u1ed3ng b\u1ed9 t\u00e0i s\u1ea3n');},
 'security-task45':async b=>{if(confirm('Ki\u1ec3m tra t\u00e0i s\u1ea3n \u0111\u00e3 \u0111\u0103ng k\u00fd v\u00e0 thu\u1ed9c quy\u1ec1n qu\u1ea3n tr\u1ecb c\u1ee7a b\u1ea1n?'))await task45(b.dataset.op,[],{asset_ids:[Number(b.dataset.id)]});},
 'security-close45':async b=>{if(confirm('\u0110\u00f3ng s\u1ef1 ki\u1ec7n b\u1ea3o m\u1eadt n\u00e0y?')){await api('/v45/security/events/'+b.dataset.id+'/close',{method:'POST',body:'{}'});await go('security');}},
 'security-identity45':async b=>modal('Identity: '+b.dataset.ip,`<p class="caption">Nh\u1eadp MAC / hostname v\u1eeba quan s\u00e1t t\u1eeb thi\u1ebft b\u1ecb ho\u1eb7c ngu\u1ed3n tin c\u1eady. Kh\u00f4ng t\u1ef1 l\u1ea5y baseline l\u00e0m b\u1eb1ng ch\u1ee9ng.</p>`+form('security-identity45-form',`<input type="hidden" name="asset_id" value="${Number(b.dataset.id)}">`+input('MAC quan s\u00e1t','observed_mac','text','',false)+input('Hostname quan s\u00e1t','observed_hostname','text','',false),'X\u00e1c nh\u1eadn quan s\u00e1t v\u00e0 so s\u00e1nh'))
});
forms['security-identity45-form']=async f=>{const v=vals(f),id=v.asset_id;delete v.asset_id;const r=await api('/v45/security/assets/'+id+'/identity',{method:'POST',body:JSON.stringify({...v,authorized:true})});$('#dialog').close();await go('security');immediate45(r,'So s\u00e1nh danh t\u00ednh thi\u1ebft b\u1ecb');};

/* Historical time windows use recorded samples, not a decorative chart. */
tr.history='Bi\u1ec3u \u0111\u1ed3 l\u1ecbch s\u1eed';groups[2][1].splice(3,0,'history');navIcon.history='\u223f';
pages.history=async()=>{const devices=await api('/managed-devices');const selection=wb45.history||{device_id:devices[0]?.id,days:1,ifindex:''};wb45.history=selection;const d=selection.device_id?await api('/v45/history/'+selection.device_id+'?days='+selection.days+(selection.ifindex?'&ifindex='+selection.ifindex:'')):{health:[],interfaces:[],ifindices:[]};const controls=form('history45-form',select('Thi\u1ebft b\u1ecb','device_id',devices.map(x=>[x.id,x.ip+' '+x.name]),selection.device_id)+select('Kho\u1ea3ng th\u1eddi gian','days',[[1,'24 gi\u1edd'],[7,'7 ng\u00e0y'],[30,'30 ng\u00e0y']],selection.days)+select('IfIndex','ifindex',[['','T\u1ea5t c\u1ea3'],...d.ifindices.map(i=>[i,i])],selection.ifindex),'Xem l\u1ecbch s\u1eed');return panel('B\u1ed9 l\u1ecdc l\u1ecbch s\u1eed',controls+'<p class="caption">T\u1ed1i \u0111a 1.000 m\u1eabu m\u1edbi nh\u1ea5t trong kho\u1ea3ng th\u1eddi gian ch\u1ecdn; bi\u1ec3u \u0111\u1ed3 hi\u1ec3n th\u1ecb 100 m\u1eabu g\u1ea7n nh\u1ea5t c\u00f3 gi\u00e1 tr\u1ecb. Kh\u00f4ng g\u00e1n s\u1ed1 0 cho d\u1eef li\u1ec7u thi\u1ebfu.</p>')+`<div class="grid2">${chart45(d.health,'cpu','CPU (%)')}${chart45(d.health,'memory','RAM (%)')}${chart45(d.health,'latency_ms','RTT (ms)')}${chart45(d.health,'packet_loss','M\u1ea5t g\u00f3i (%)')}</div>`+panel('M\u1eabu t\u00e0i nguy\u00ean',rows45(d.health))+panel('M\u1eabu interface / l\u01b0u l\u01b0\u1ee3ng',rows45(d.interfaces));};
forms['history45-form']=async f=>{const v=vals(f);wb45.history={device_id:Number(v.device_id),days:Number(v.days),ifindex:v.ifindex};await go('history');};
const oldAudit45=pages.auditall;
tr.auditall='Ki\u1ec3m tra d\u1eef li\u1ec7u / c\u1ea5u h\u00ecnh';
pages.auditall=async()=>'<div class="inline-notice">PASS \u1edf trang n\u00e0y ch\u1ec9 l\u00e0 ki\u1ec3m tra c\u1ea5u h\u00ecnh / d\u1eef li\u1ec7u n\u1ed9i b\u1ed9, kh\u00f4ng ph\u1ea3i k\u1ebft qu\u1ea3 SSH, SNMP, Backup/Restore tr\u00ean thi\u1ebft b\u1ecb th\u1eadt.</div>'+await oldAudit45();


/* Desktop navigation map. Not a production acceptance certificate. */
const parityRows45=[{"desktop": "Dashboard / NOC", "page": "dashboard", "boundary": "Overview and recorded observations"}, {"desktop": "Device Manager / Network Devices", "page": "managed", "boundary": "Inventory and managed-device metadata; connection setup"}, {"desktop": "Ping Monitor", "page": "pingmonitor", "boundary": "CRUD/import targets; one cycle / repeat / stop; per-IP observations"}, {"desktop": "Network Scan / Auto Discovery", "page": "scan", "boundary": "Authorized subnet discovery; explicit import to inventory"}, {"desktop": "IP / MAC Manager", "page": "ipmac", "boundary": "Add/edit/delete; conflict view; import latest scan"}, {"desktop": "Auto IP", "page": "autoip", "boundary": "Shared desktop engine: full options, targets, profiles, step results, history, reports"}, {"desktop": "CPU / RAM / Advanced Ports / Multi Port", "page": "monitoringx", "boundary": "Shared resource/interface collectors; async jobs; IfIndex selection"}, {"desktop": "History Charts", "page": "history", "boundary": "24h / 7d / 30d recorded samples; no fabricated missing measurements"}, {"desktop": "Network Health / SNMP Diagnostics", "page": "health", "boundary": "Real observations and shared credential-driven diagnostics"}, {"desktop": "SNMPv2c / SNMPv3 / Credential Manager", "page": "credentials", "boundary": "Encrypted assignments; no automatic SSH host trust"}, {"desktop": "Device Profiles / Vendor Drivers", "page": "profiles", "boundary": "Profiles and driver assignments"}, {"desktop": "Topology / Dependencies", "page": "topology", "boundary": "LLDP/CDP collection and dependency actions"}, {"desktop": "Organization / Sites / Device Groups", "page": "organization", "boundary": "Organization management"}, {"desktop": "Alert Rules / Alerts", "page": "rules", "boundary": "Rules; lifecycle actions on Alerts page"}, {"desktop": "Incidents / RCA", "page": "incidents", "boundary": "Incident state and root-cause analysis"}, {"desktop": "Service Impact", "page": "services", "boundary": "Services and dependency impact"}, {"desktop": "SLA / Maintenance / Capacity Planning", "page": "sla", "boundary": "Policies, maintenance windows and capacity results"}, {"desktop": "Application / Server", "page": "server", "boundary": "Targets, checks, history and validation"}, {"desktop": "SSH Automation / Audit", "page": "audit", "boundary": "Registered targets; credentials and verified host keys required"}, {"desktop": "Backup / Secure Backup / Scheduler", "page": "backup", "boundary": "Actual shared backup functions and scheduled jobs"}, {"desktop": "Config Compare / Security Audit", "page": "compare", "boundary": "Configuration comparison and posture checks"}, {"desktop": "Restore Config", "page": "restore", "boundary": "Guarded restore; vendor limitations and mandatory lab acceptance"}, {"desktop": "Notifications", "page": "notify", "boundary": "Configuration and explicitly confirmed async tests"}, {"desktop": "Enterprise Security", "page": "security", "boundary": "Registered asset sync; TCP / TLS fingerprint / identity; event closure"}, {"desktop": "Daily Audit Windows", "page": "dailyaudit", "boundary": "Requires Windows and local tool permissions"}, {"desktop": "Remote Service", "page": "remote", "boundary": "Connectivity checks and RDP file; native client remains on operator machine"}, {"desktop": "Scheduled Tasks", "page": "scheduler", "boundary": "Web job scheduler; review imported schedules before enabling"}, {"desktop": "Reports / Disaster Recovery", "page": "reports", "boundary": "Exports and download links; guarded recovery workflow"}, {"desktop": "User Roles / Audit / Logs / Settings", "page": "accounts", "boundary": "RBAC plus individual log/audit/settings pages"}, {"desktop": "Windows Monitoring Service", "page": "production", "boundary": "OS service install/start is local; browser does not install Windows services"}];
tr.parity='Desktop / Web 4.5';
pages.parity=async()=>panel('Desktop / Web 4.5', '<p class="caption">This is a feature navigation map, not proof of real-device success. SSH/SNMP/Backup/Restore require credentials, network access and device acceptance. Native RDP and Windows service management remain local.</p>'+table(parityRows45,[['Desktop','desktop'],['Web','page'],['Implementation / boundary','boundary']],r=>button('Open','page',{page:r.page})));

/* Form errors stay with their form instead of disappearing in a toast. */
for(const [id,fn] of Object.entries(forms)){
  if(id==='login-form')continue;
  forms[id]=async f=>{f.querySelector('.inline-form-error')?.remove();try{return await fn(f);}catch(e){const error=document.createElement('div');error.className='error inline-form-error wide-field';error.setAttribute('role','alert');error.textContent=e.message;f.append(error);throw e;}};
}
// The already-running initial login from app.js resolves after this script loads.

window.addEventListener('na46:logout',()=>{
 for(const value of wb45.watchers.values())if(value?.timer)clearTimeout(value.timer);
 wb45.watchers.clear();wb45.operations.clear();wb45.selectedJob.clear();wb45.grids.clear();wb45.pageScroll.clear();
 wb45.ping=null;wb45.auto=null;wb45.autoSteps=[];wb45.activeRun='';
 if($('#content'))$('#content').innerHTML='';if($('#operation-result')){$('#operation-result').innerHTML='';$('#operation-result').classList.add('hidden');}
});
document.addEventListener('change',e=>{
  const id=e.target?.dataset?.ipmacSelect;if(!id)return;
  wb45.ipmacSelected=wb45.ipmacSelected||new Set();
  const n=Number(id);if(e.target.checked)wb45.ipmacSelected.add(n);else wb45.ipmacSelected.delete(n);
  const c=document.getElementById('ipmac-selected-count');if(c)c.textContent='Đã chọn '+wb45.ipmacSelected.size;
});


/* 6.2.4 richer live connected-device discovery */
async function refreshConnected624(){
  if(state.page!=='ipmac')return;
  const box=document.getElementById('connected-devices623');if(!box)return;
  try{
    const r=await api('/v50/connected-devices');
    const items=(r.devices||[]);
    const c=r.source_counts||{};
    const summary=['ICMP','ARP','DHCP','MDNS','SSDP','NETBIOS'].filter(k=>Number(c[k]||0)>0).map(k=>`${k} ${c[k]}`).join(' · ');
    box.innerHTML=`<b>Thiết bị đang kết nối:</b> ${esc(items.length)} thiết bị${summary?' · '+esc(summary):''} · mạng ${esc(r.network||'—')} · cập nhật ${esc(r.completed_at||'chưa có')}`+
      (items.length?`<details><summary>Xem danh sách đang kết nối</summary><div class="table-wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Nguồn phát hiện</th><th>Độ trễ</th></tr></thead><tbody>${items.slice(0,512).map(x=>`<tr><td>${esc(x.ip||'')}</td><td>${esc(x.mac||'')}</td><td>${esc(x.hostname||'')}</td><td>${(x.sources||[]).map(s=>badge(s)).join(' ')||badge('LAN')}</td><td>${x.latency_ms==null?'—':esc(x.latency_ms)+' ms'}</td></tr>`).join('')}</tbody></table></div></details>`:'');
  }catch(e){box.innerHTML=`<b>Thiết bị đang kết nối:</b> chưa đọc được dữ liệu (${esc(e.message||String(e))})`;}
}
const _oldIpMac623=pages.ipmac;
pages.ipmac=async()=>{const h=await _oldIpMac623();setTimeout(()=>void refreshConnected624(),0);return h;};
window.addEventListener('na46:ready',()=>{setInterval(()=>{if(state.user&&state.page==='ipmac'&&document.visibilityState==='visible')void refreshConnected624();},5000);});
