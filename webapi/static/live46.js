'use strict';
/* No reload/navigation from background work. All polls are single-flight. */
const refresh46 = {busy:false,dirty:new WeakSet(),last:0,health:0,failures:0,updates:0,skipped:0};
function dirty46(){return [...document.querySelectorAll('#content form')].some(f=>refresh46.dirty.has(f));}
function editing46(){const a=document.activeElement;return $('#dialog').open||dirty46()||a?.matches('input,textarea,select,[contenteditable=true]')||!window.getSelection()?.isCollapsed;}
window.naRefresh46={clean:f=>refresh46.dirty.delete(f),stats:refresh46};
for(const name of ['input','change'])document.addEventListener(name,e=>{const f=e.target.closest('#content form');if(f)refresh46.dirty.add(f);});
function banner46(message,error=false){const b=$('#connection-banner');if(!b)return;b.textContent=message;b.classList.toggle('hidden',!message);b.classList.toggle('error',error);}
/* Morph only trusted HTML assembled by local renderers, never remote terminal output.
   Keep forms, inputs, open details and scroll containers as the very same DOM nodes. */
function patchNode46(old,fresh){
  if(old.nodeType!==fresh.nodeType||(old.nodeType===1&&(old.tagName!==fresh.tagName||old.id!==fresh.id))){old.replaceWith(fresh.cloneNode(true));return;}
  if(old.nodeType===3){if(old.nodeValue!==fresh.nodeValue)old.nodeValue=fresh.nodeValue;return;}
  if(old.nodeType!==1)return;
  if(old.matches('form,input,textarea,select,[data-preserve],#terminal-workspace'))return;
  for(const a of [...old.attributes])if(a.name!=='open'&&!fresh.hasAttribute(a.name))old.removeAttribute(a.name);
  for(const a of [...fresh.attributes])if(a.name!=='open'&&old.getAttribute(a.name)!==a.value)old.setAttribute(a.name,a.value);
  const before=[...old.childNodes],after=[...fresh.childNodes];
  for(let i=0;i<Math.max(before.length,after.length);i++){
    if(!after[i])before[i]?.remove();else if(!before[i])old.append(after[i].cloneNode(true));else patchNode46(before[i],after[i]);
  }
}
window.patchHTML46=function(host,html){
 if(!host)return;
 const t=document.createElement('template');t.innerHTML=html;const fresh=host.cloneNode(false);fresh.append(t.content);
 // Legacy table() gives anonymous grids new serial IDs on every render. Rebind
 // compatible table slots before morphing, preserving search, sort and pagination.
 const oldGrids=[...host.querySelectorAll('.data-grid')];
 for(const [i,grid] of [...fresh.querySelectorAll('.data-grid')].entries()){
  const old=oldGrids[i];
  if(!old||!/^grid45-\d+$/.test(grid.id)||!/^grid45-\d+$/.test(old.id)||old.id===grid.id)continue;
  const prev=wb45.grids.get(old.id),next=wb45.grids.get(grid.id);
  if(!prev||!next||JSON.stringify(prev.cols.map(c=>c[1]))!==JSON.stringify(next.cols.map(c=>c[1])))continue;
  wb45.grids.delete(grid.id);Object.assign(next,{filter:prev.filter,page:prev.page,sortKey:prev.sortKey,direction:prev.direction,size:prev.size});
  wb45.grids.set(old.id,next);grid.id=old.id;grid.innerHTML=gridMarkup45(old.id);
 }
 patchNode46(host,fresh);
};
window.refreshPage46=async function(page=state.page){
  if(!state.user||state.page!==page||refresh46.busy||state.busy||page==='terminal'||$('#terminal-workspace')?.contains(document.activeElement))return;
  if(editing46()){refresh46.skipped++;return;}
  refresh46.busy=true;const epoch=state.render,scroll=window.scrollY;
  try{
    if(page==='pingmonitor')await refreshPing45();
    else if(page==='autoip')await refreshAuto45();
    else{
      const html=await pages[page]();
      if(epoch!==state.render||page!==state.page||editing46()||state.busy||!state.user)return;
      window.patchHTML46($('#content'),html);
    }
    if(epoch!==state.render||page!==state.page)return;
    refresh46.updates++;refresh46.failures=0;banner46('');
    $('#updated-at').textContent='C\u1eadp nh\u1eadt '+new Date().toLocaleTimeString();
    window.scrollTo(0,scroll);
  }catch(e){refresh46.failures++;if(epoch===state.render&&state.user)banner46('Ch\u01b0a l\u1ea5y \u0111\u01b0\u1ee3c d\u1eef li\u1ec7u m\u1edbi. Gi\u1eef nguy\u00ean trang; s\u1ebd th\u1eed l\u1ea1i. '+e.message,true);}
  finally{refresh46.busy=false;}
};
/* Intentional navigation only. A refresh never goes through this function. */
go=async function(page){
  if(!pages[page])return;
  const same=state.page===page,scroll=window.scrollY;
  if(dirty46()&&!window.naRefresh46.inSubmit&&!confirm('Bi\u1ec3u m\u1eabu c\u00f3 thay \u0111\u1ed5i ch\u01b0a l\u01b0u. Ti\u1ebfp t\u1ee5c v\u00e0 b\u1ecf c\u00e1c thay \u0111\u1ed5i?'))return;
  if(!same)wb45.pageScroll.set(state.page,scroll);
  state.page=page;const epoch=++state.render;navigation();renderOperationResult();
  $('#title').textContent=tr[page]||page;
  $('#subtitle').textContent='Cybersecurity 5.9.2 \u00b7 C\u1eadp nh\u1eadt t\u1ea1i ch\u1ed7 \u00b7 Kh\u00f4ng t\u1ef1 t\u1ea3i l\u1ea1i trang';
  $('#live-toggle').textContent='L\u00e0m m\u1edbi: '+(state.live?'B\u1eacT':'T\u1eaeT');
  $('#terminal-workspace').classList.toggle('hidden',page!=='terminal');
  window.dispatchEvent(new CustomEvent('na46:navigate',{detail:{page}}));
  if(!same)$('#content').innerHTML='<div class="spinner">\u0110ang m\u1edf m\u1ee5c...</div>';
  try{
    const html=await pages[page]();if(epoch!==state.render||!state.user)return;
    $('#content').innerHTML=html;banner46('');
    if(location.hash.slice(1)!==page)history.replaceState(null,'','#'+page);
    $('#updated-at').textContent='C\u1eadp nh\u1eadt '+new Date().toLocaleTimeString();
    renderOperationResult();window.dispatchEvent(new CustomEvent('na46:ready',{detail:{page}}));
    window.scrollTo(0,same?scroll:(wb45.pageScroll.get(page)||0));
  }catch(e){if(epoch===state.render){if(!same)$('#content').innerHTML=`<div class="error">${esc(e.message)}</div>`;else banner46(e.message,true);}}
};
actions.reload=async()=>{if(state.page==='terminal'){await healthCheck();toast('Terminal gi\u1eef nguy\u00ean; kh\u00f4ng t\u1ef1 k\u1ebft n\u1ed1i l\u1ea1i.');return;}if(dirty46()){toast('H\u00e3y l\u01b0u ho\u1eb7c b\u1ecf thay \u0111\u1ed5i trong bi\u1ec3u m\u1eabu tr\u01b0\u1edbc khi l\u00e0m m\u1edbi.');return;}await go(state.page);};
actions['live-toggle']=async()=>{state.live=!state.live;try{sessionStorage.setItem('na46_live',String(state.live));}catch{}$('#live-toggle').textContent='L\u00e0m m\u1edbi: '+(state.live?'B\u1eacT':'T\u1eaeT');toast(state.live?'C\u1eadp nh\u1eadt d\u1eef li\u1ec7u t\u1ea1i ch\u1ed7.':'T\u1ea1m d\u1eebng l\u00e0m m\u1edbi, kh\u00f4ng d\u1eebng t\u00e1c v\u1ee5.');};
try{if(sessionStorage.getItem('na46_live')==='false')state.live=false;}catch{}
const livePages46=new Set(['dashboard','devices','server','health','alerts','incidents','sla','topology','extensions','lan','security','logs','readiness','jobs','scheduler','production','auditall','pingmonitor','autoip']);
async function tick46(){
  const now=Date.now();
  if(now-refresh46.health>15000){refresh46.health=now;void healthCheck();}
  const normalDelay=['pingmonitor','autoip'].includes(state.page)?2000:15000;
  const delay=Math.min(60000,normalDelay*Math.pow(2,Math.min(refresh46.failures,4)));
  if(window.ops47?.offline){setTimeout(tick46,2000);return;}
  if(!document.hidden&&state.user&&state.live&&livePages46.has(state.page)&&now-refresh46.last>delay){refresh46.last=now;await window.refreshPage46(state.page);}
  setTimeout(tick46,1000);
}
setTimeout(tick46,1500);
window.addEventListener('beforeunload',e=>{if(dirty46()||window.terminal46?.hasOpen()){e.preventDefault();e.returnValue='';}});
