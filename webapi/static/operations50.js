/* NetworkAutomation Web 5.0 production overlay. */
(()=>{
if(!window.__NA47_LOADED__ && typeof pages==='undefined') return;
window.__NA50_LOADED__=true;
tr.platform50='Nền tảng 5.0';navIcon.platform50='◉';
if(!groups[5][1].includes('platform50')) groups[5][1].unshift('platform50');

const diagStep50=s=>`<tr><td>${esc(s.step||'')}</td><td>${badge(s.status||'Unknown')}</td><td>${esc(s.code||'')}</td><td>${esc(s.detail||'')}</td><td>${s.elapsed_ms==null?'—':esc(s.elapsed_ms)+' ms'}</td></tr>`;
const cameraResult50=r=>`<div class="cards">${metric('Kết quả',r.status,r.status==='PASS'?'green':'red')}${metric('Mã',r.code||'—')}${metric('Thời gian',Math.round(r.elapsed_ms||0)+' ms')}${metric('Cổng',r.port)}</div><p class="caption">${esc(r.meaning||'')}</p><div class="table-wrap"><table><thead><tr><th>Bước</th><th>Trạng thái</th><th>Mã</th><th>Chi tiết</th><th>Thời gian</th></tr></thead><tbody>${(r.steps||[]).map(diagStep50).join('')}</tbody></table></div>`;

pages.extensions=async()=>{
 const e=await api('/v4/extensions');state.cameras=e.cameras;const w=e.wifi_status||{};
 const hist=(e.history||[]).map(x=>{let detail=x.detail;try{const j=JSON.parse(detail);detail=j.code?`${j.code} · ${j.meaning||''}`:detail}catch{}return {...x,detail}});
 return `<div class="cards">${metric('Camera / NVR',e.cameras.length)}${metric('Wi‑Fi',w.status||(e.wifi_supported?'PASS':'N/A'))}${metric('Lịch sử',e.history.length)}${metric('Chẩn đoán','5.0','green')}</div>`+
 panel('Wi‑Fi diagnostics 5.0',`<p class="caption">Giữ mã lỗi Windows thay vì gom tất cả thành một cảnh báo chung. Không thay đổi cấu hình Wi‑Fi.</p><div class="notice">${esc(w.detail||'')}</div>${canWrite()?button('Chạy chẩn đoán Wi‑Fi','wifi-diagnose50',{},'primary'):''}`)+
 panel('Camera / NVR endpoints',table(e.cameras,[['ID','id'],['Tên','name'],['Host','host'],['Port','port'],['Stream config','has_stream',v=>badge(v?'Đã lưu':'Chưa lưu')],['Snapshot config','has_snapshot',v=>badge(v?'Đã lưu':'Chưa lưu')]],r=>canWrite()?button('Chẩn đoán','camera-diagnose50',{id:r.id},'primary')+(isAdmin()?button('Sửa','camera-edit',{id:r.id})+button('Xóa','camera-delete',{id:r.id},'danger'):''):''),isAdmin()?button('Thêm camera','camera-add'): '')+
 panel('Lịch sử chẩn đoán',table(hist,[['Loại','kind'],['Đích','target'],['Trạng thái','status',badge],['Chi tiết','detail'],['Thời gian','created_at']]));
};

pages.platform50=async()=>{
 if(!isAdmin())return `<div class="empty"><b>Admin only</b>Trang này hiển thị trạng thái triển khai và Windows Service.</div>`;
 const [a,s,r]=await Promise.all([api('/v50/about'),api('/v50/service'),api('/v50/readiness')]);
 const ready=Object.values(r.python_dependencies||{}).filter(Boolean).length,net=r.network||{};
 return `<div class="cards">${metric('Phiên bản',a.version,'green')}${metric('Chế độ',a.run_mode)}${metric('Mạng',net.mode||'UNKNOWN',net.wan?'green':net.lan?'amber':'red')}${metric('Windows Service',s.state,s.state==='RUNNING'?'green':s.state==='NOT_INSTALLED'?'amber':'')}${metric('Python libs',ready+'/'+Object.keys(r.python_dependencies||{}).length)}</div>`+
 panel('Kết nối mạng lúc khởi động',networkDetails50(net))+
 panel('Production readiness',`<div class="checks47">${Object.entries(r.python_dependencies||{}).map(([k,v])=>`<div><span>${esc(k)}</span><strong>${badge(v?'READY':'MISSING')}</strong></div>`).join('')}${Object.entries(r.executables||{}).map(([k,v])=>`<div><span>${esc(k+' executable')}</span><strong>${badge(v?'READY':'MISSING')}</strong></div>`).join('')}</div>${(r.warnings||[]).map(x=>`<div class="notice">${esc(x)}</div>`).join('')}`)+
 panel('Windows Service',`<p><b>${esc(s.name)}</b> · ${badge(s.state)}</p><p class="caption">${esc(s.note||'')}</p><p class="caption">Cài cục bộ bằng <code>${esc(s.install_script||'INSTALL_WEB_SERVICE.bat')}</code>. Gỡ bằng <code>${esc(s.remove_script||'REMOVE_WEB_SERVICE.bat')}</code>. Web không tự dừng chính tiến trình đang phục vụ yêu cầu.</p>`)+
 panel('Nguyên tắc 5.0',`<div class="notice">${esc(a.principle)}</div><p class="caption">5.0 ưu tiên bằng chứng thực thi: TCP mở không đồng nghĩa camera xem được; Completed không đồng nghĩa mọi thiết bị khỏe; lỗi công cụ không bị đổi thành Offline.</p>`);
};

actions['camera-diagnose50']=async b=>{
 const id=Number(b.dataset.id); if(!id)return;
 modal('Đang chẩn đoán camera/NVR','<div class="empty"><b>Đang chạy</b>Phân giải địa chỉ → ICMP tham khảo → TCP. Tối đa 5 giây cho kết nối TCP.</div>');
 try{const r=await api('/v50/cameras/'+id+'/diagnose',{method:'POST',body:JSON.stringify({timeout_seconds:5})});modal('Kết quả camera/NVR · '+esc(r.name||''),cameraResult50(r));}
 catch(e){modal('Chẩn đoán thất bại',`<div class="error">${esc(e.message||String(e))}</div>`)}
};
actions['wifi-diagnose50']=async()=>{
 modal('Wi‑Fi diagnostics','<div class="empty"><b>Đang chạy</b>Đọc adapter, interface, mạng lân cận, gateway và phép đo ICMP tham khảo.</div>');
 try{const r=await api('/v50/wifi/diagnose',{method:'POST',body:JSON.stringify({gateway:'',internet:'1.1.1.1'})});
 const steps=(r.steps||[]).map(diagStep50).join('');
 modal('Kết quả Wi‑Fi',`<div class="cards">${metric('Trạng thái',r.status,r.status==='PASS'?'green':'amber')}${metric('Adapter',(r.adapters||[]).length)}${metric('Thời gian',r.checked_at||'—')}</div><p class="caption">${esc(r.detail||'')}</p><div class="table-wrap"><table><thead><tr><th>Bước</th><th>Trạng thái</th><th>Mã</th><th>Chi tiết</th><th></th></tr></thead><tbody>${steps}</tbody></table></div><details><summary>Thông tin interface</summary><pre>${esc(r.interfaces||'')}</pre></details><details><summary>Mạng lân cận</summary><pre>${esc(r.nearby_networks||'')}</pre></details>`);
 }catch(e){modal('Wi‑Fi diagnostics thất bại',`<div class="error">${esc(e.message||String(e))}</div>`)}
};


const net50={last:0,data:null,timer:null,busy:false};
function ensureNetworkChip50(){
 let chip=document.querySelector('#network-state50');
 if(chip)return chip;
 chip=document.createElement('button');chip.id='network-state50';chip.type='button';chip.dataset.action='network-detail50';chip.className='network-chip50 unknown';chip.textContent='Mạng: đang kiểm tra';
 const apiState=document.querySelector('#api-state');if(apiState?.parentNode)apiState.parentNode.insertBefore(chip,apiState.nextSibling);
 return chip;
}
function paintNetwork50(r){
 const chip=ensureNetworkChip50();const mode=r?.mode||'UNKNOWN';
 const label={ 'LAN+WAN':'LAN + WAN','LAN_ONLY':'LAN','WAN':'WAN','LINK_LOCAL':'Link-local','OFFLINE':'Offline' }[mode]||'Không rõ';
 chip.textContent='Mạng: '+label;chip.className='network-chip50 '+(r?.wan?'online':r?.lan?'lan':'offline');chip.title=r?.meaning||'';
 const banner=document.querySelector('#connection-banner');
 if(banner){
   if(mode==='OFFLINE'||mode==='LINK_LOCAL'){banner.textContent=r.meaning||'Chưa xác minh được kết nối mạng.';banner.classList.remove('hidden');banner.classList.add('error');}
   else if(banner.textContent?.startsWith('Chưa phát hiện LAN')||banner.textContent?.startsWith('Chỉ phát hiện địa chỉ')){banner.textContent='';banner.classList.add('hidden');banner.classList.remove('error');}
 }
}
async function checkNetwork50(force=false){
 if(net50.busy||!state.user)return net50.data;if(browser16n.active){paintBrowserNetwork16n();return {mode:'WEB',wan:true,lan:false,meaning:'Web browser'};}net50.busy=true;
 try{const r=await api('/v50/network/connectivity'+(force?'?force=true':''));net50.data=r;net50.last=Date.now();paintNetwork50(r);return r;}
 catch(e){const chip=ensureNetworkChip50();chip.textContent='Mạng: lỗi kiểm tra';chip.className='network-chip50 offline';chip.title=e.message||String(e);return null;}
 finally{net50.busy=false;}
}
const networkDetails50=r=>{
 const adapters=(r.adapters||[]).map(a=>`<tr><td>${esc(a.name||'')}</td><td>${esc((a.ipv4||[]).join(', '))}</td><td>${esc(a.gateway||'—')}</td></tr>`).join('');
 const checks=(r.wan_checks||[]).map(x=>`<tr><td>${esc(x.target||'')}</td><td>${badge(x.ok?'PASS':'FAIL')}</td><td>${x.elapsed_ms==null?'—':esc(x.elapsed_ms)+' ms'}</td></tr>`).join('');
 return `<div class="cards">${metric('Chế độ',r.mode||'UNKNOWN',r.wan?'green':r.lan?'amber':'red')}${metric('LAN',r.lan?'Có':'Không',r.lan?'green':'')}${metric('WAN / Internet',r.wan?'Có':'Không',r.wan?'green':'red')}${metric('Kiểm tra lúc',r.checked_at||'—')}</div><div class="notice">${esc(r.meaning||'')}</div><h3>Adapter đang hoạt động</h3><div class="table-wrap"><table><thead><tr><th>Adapter</th><th>IPv4</th><th>Gateway</th></tr></thead><tbody>${adapters||'<tr><td colspan="3">Không phát hiện adapter IPv4 đang hoạt động.</td></tr>'}</tbody></table></div><h3>Kiểm tra WAN</h3><div class="table-wrap"><table><thead><tr><th>Đích kiểm tra</th><th>Kết quả</th><th>Thời gian</th></tr></thead><tbody>${checks||'<tr><td colspan="3">Chưa có phép kiểm tra.</td></tr>'}</tbody></table></div><p class="caption">Kiểm tra WAN chỉ thử kết nối TCP ra ngoài, không thay đổi cấu hình mạng. Trên bản Web host, LAN private của thiết bị người dùng không được quét từ máy chủ.</p>`;
};
actions['network-detail50']=async()=>{const r=await checkNetwork50(true);if(r)modal('Kết nối mạng hiện tại',networkDetails50(r));};



const browser16n={active:false,probe:null,timer:null};
async function checkBrowser16n(){
 if(!state.user)return null;
 try{const p=await api('/v59/browser/probe?ts='+Date.now());browser16n.active=true;browser16n.probe=p;paintBrowserIp16n(p);paintBrowserNetwork16n(p);return p;}
 catch(e){browser16n.active=false;const net=ensureNetworkChip50();net.textContent='Mạng: lỗi';net.className='network-chip50 offline';net.title=e.message||String(e);const ip=ensureIpChip5011();ip.textContent='IP mạng: lỗi';ip.className='network-chip50 offline';return null;}
}
function paintBrowserIp16n(p){const chip=ensureIpChip5011();const ip=p?.public_ip||'';ip5011.data={source:'BROWSER',ipv4:ip,adapter:'Browser / HTTPS',network:'',gateway:''};chip.textContent='IP mạng: '+(ip||'—');chip.className='network-chip50 '+(ip?'online':'unknown');chip.title='IP Internet công khai của thiết bị đang mở Web, tự nhận từ kết nối HTTPS.';}
function paintBrowserNetwork16n(){const chip=ensureNetworkChip50();chip.textContent='Mạng: WEB';chip.className='network-chip50 online';chip.title='Web đang hoạt động và kiểm tra kết nối trực tiếp từ trình duyệt.';}

const ip5011={data:null,busy:false};
function ensureIpChip5011(){
 let chip=document.querySelector('#server-ip5011');
 if(chip)return chip;
 chip=document.createElement('button');chip.id='server-ip5011';chip.type='button';chip.dataset.action='ip-detail5011';chip.className='network-chip50 unknown';chip.textContent='IP: đang kiểm tra';
 const net=document.querySelector('#network-state50'),apiState=document.querySelector('#api-state');
 if(net?.parentNode)net.parentNode.insertBefore(chip,net.nextSibling);else if(apiState?.parentNode)apiState.parentNode.insertBefore(chip,apiState);
 return chip;
}
function paintIp5011(r){
 const chip=ensureIpChip5011();ip5011.data=r;const ip=r?.ipv4||'';
 chip.textContent='IP mạng: '+(ip||'không có');chip.className='network-chip50 '+(ip?'online':'offline');
 chip.title=ip?`${r.adapter||'Browser / HTTPS'} · IP Internet công khai`:'Không xác định được IP mạng.';
 if(r?.changed_since_start){chip.className='network-chip50 lan';chip.textContent='IP đổi: '+ip;}
}
async function checkIp5011(force=false){
 if(ip5011.busy||!state.user)return ip5011.data;if(browser16n.active&&browser16n.probe){paintBrowserIp16n(browser16n.probe);return ip5011.data}ip5011.busy=true;
 try{const r=await api('/v50/network/identity'+(force?'?force=true':''));paintIp5011(r);return r;}
 catch(e){if(browser16n.active&&browser16n.probe){paintBrowserIp16n(browser16n.probe);return ip5011.data}const chip=ensureIpChip5011();chip.textContent='IP: lỗi kiểm tra';chip.className='network-chip50 offline';chip.title=e.message||String(e);return null;}
 finally{ip5011.busy=false;}
}
actions['ip-detail5011']=async()=>{
 const r=await checkIp5011(true);if(!r)return;modal('Địa chỉ mạng của thiết bị đang mở Web',`<div class="cards">${metric('IP Internet công khai',r.ipv4||'Không có',r.ipv4?'green':'')}${metric('Nguồn','HTTPS')}${metric('Chế độ','WEB')}</div><div class="notice"><b>Tự động:</b> Web đọc IP công khai từ kết nối đang truy cập trang, không cần cài hay chạy chương trình khác.</div><p class="caption">Trình duyệt hiện đại không cho website đọc ổn định IP private 192.168.x.x, gateway, bảng ARP/MAC hoặc quét LAN. Vì vậy Web hiển thị địa chỉ Internet thực sự mà máy chủ nhìn thấy.</p>`);
};

const discovery5010={timer:null,busy:false,last:null};
function ensureDiscoveryChip5010(){
 let chip=document.querySelector('#startup-scan5010');
 if(chip)return chip;
 chip=document.createElement('button');chip.id='startup-scan5010';chip.type='button';chip.dataset.action='startup-scan-detail5010';chip.className='network-chip50 unknown';chip.textContent='IP đang dùng: chờ';
 const net=document.querySelector('#network-state50'),apiState=document.querySelector('#api-state');
 if(net?.parentNode)net.parentNode.insertBefore(chip,net.nextSibling);else if(apiState?.parentNode)apiState.parentNode.insertBefore(chip,apiState);
 return chip;
}
function paintDiscovery5010(r){
 const chip=ensureDiscoveryChip5010();discovery5010.last=r;const st=r?.state||'IDLE';
 if(st==='RUNNING'||st==='QUEUED'){const a=r.active??r.preliminary_active??0,p=r.progress_total?` ${r.progress_done||0}/${r.progress_total}`:'';chip.textContent=`IP đang dùng: ${a} · đang quét${p}`;chip.className='network-chip50 lan';}
 else if(st==='COMPLETED'||st==='RECENT'){chip.textContent=`IP đang dùng: ${r.active??r.online??0}`;chip.className='network-chip50 online';}
 else if(st==='COMPLETED_WITH_ERRORS'){chip.textContent=`IP đang dùng: ${r.active??r.online??0} · có lỗi`;chip.className='network-chip50 lan';}
 else if(st==='SKIPPED'){chip.textContent='IP đang dùng: bỏ qua';chip.className='network-chip50 unknown';}
 else if(st==='FAILED'){chip.textContent='IP đang dùng: lỗi';chip.className='network-chip50 offline';}
 else if(st==='BROWSER_ONLY'){chip.textContent='LAN: không khả dụng';chip.className='network-chip50 unknown';}
 else{chip.textContent='IP đang dùng: chờ';chip.className='network-chip50 unknown';}
 chip.title=r?.detail||'';
}
async function ensureStartupDiscovery5010(){
 if(discovery5010.busy||!state.user)return;discovery5010.busy=true;
 try{const r=await api('/v50/startup-discovery/ensure',{method:'POST',body:'{}'});paintDiscovery5010(r);}
 catch(e){const chip=ensureDiscoveryChip5010();chip.textContent='IP đang dùng: không chạy';chip.className='network-chip50 offline';chip.title=e.message||String(e);}
 finally{discovery5010.busy=false;}
}
async function pollDiscovery5010(){
 if(!state.user)return;try{const r=await api('/v50/startup-discovery');paintDiscovery5010(r);if(state.page==='ipmac'&&(r.state==='COMPLETED'||r.state==='COMPLETED_WITH_ERRORS')&&typeof window.refreshPage46==='function')void window.refreshPage46(state.page);}catch{}
}
function discoveryDetailHtml5016(r){
 const running=r.state==='RUNNING'||r.state==='QUEUED';
 const progress=r.progress_total?`${r.progress_done||0}/${r.progress_total}`:(running?'đang chuẩn bị':'—');
 return `<div class="cards">${metric('Trạng thái',r.state||'IDLE')}${metric('Subnet',r.network||'—')}${metric('IP đang dùng',r.active??r.online??0,'green')}${metric('ICMP phản hồi',r.icmp_online??r.online??0)}${metric('LAN thụ động',r.arp_only??r.preliminary_active??0)}${metric('Đồng bộ IP/MAC',r.imported||0)}${metric('Tiến độ',progress)}</div><div class="notice">${esc(r.detail||'')}</div><p class="caption">Quét ưu tiên ARP/neighbor để hiện thiết bị sớm, sau đó ICMP và hợp nhất DHCP/mDNS/SSDP. Thiết bị chặn ping vẫn có thể được nhận diện từ bằng chứng LAN. Không tự quét WAN/Internet và không tự gán credential.</p>${canWrite()?button(running?'Đang quét…':'Quét lại ngay','startup-scan-force5010',{},running?'':'primary'):''}`;
}
let discoveryDetailToken5016=0;
async function refreshDiscoveryDetail5016(token){
 const dlg=document.querySelector('#dialog');
 if(token!==discoveryDetailToken5016||!dlg?.open)return;
 try{
   const r=await api('/v50/startup-discovery');paintDiscovery5010(r);
   if(token!==discoveryDetailToken5016||!dlg?.open)return;
   const body=document.querySelector('#dialog-body');if(body)body.innerHTML=discoveryDetailHtml5016(r);
   if(r.state==='RUNNING'||r.state==='QUEUED')setTimeout(()=>void refreshDiscoveryDetail5016(token),1000);
 }catch{}
}
actions['startup-scan-detail5010']=async()=>{
 let r=discovery5010.last;try{r=await api('/v50/startup-discovery')}catch{}
 if(!r)return;
 modal('IP đang dùng trong cùng mạng',discoveryDetailHtml5016(r));
 const token=++discoveryDetailToken5016;
 if(r.state==='RUNNING'||r.state==='QUEUED')setTimeout(()=>void refreshDiscoveryDetail5016(token),700);
};
actions['startup-scan-force5010']=async()=>{try{const r=await api('/v50/startup-discovery/ensure?force=true',{method:'POST',body:'{}'});paintDiscovery5010(r);toast('Đã yêu cầu quét IP đang dùng trong LAN.');}catch(e){toast(e.message||String(e),true)}};

window.addEventListener('na46:ready',()=>{
 const n=document.querySelector('.brand small');if(n)n.textContent='Cybersecurity / UI 6.9.0';const notice=document.querySelector('main>.notice');if(notice)notice.textContent='NetworkAutomation Web: tự nhận IP Internet công khai và đo kết nối từ thiết bị đang mở trang.';
 ensureNetworkChip50();ensureIpChip5011();void checkBrowser16n().then(()=>{void checkNetwork50(false);void checkIp5011(false);});
 if(!browser16n.timer)browser16n.timer=setInterval(()=>{if(state.user&&document.visibilityState==='visible')void checkBrowser16n().then(()=>{void checkNetwork50(true);void checkIp5011(true);});},60000);
});
})();
