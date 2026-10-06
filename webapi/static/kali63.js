'use strict';
/* Kali Linux integration: defensive/authorized execution backend only. */
(()=>{
  tr.kali63='Kali Linux Integration'; navIcon.kali63='🐉';
  const whiteGroup=groups.find(g=>String(g[0]).includes('HACKER MŨ TRẮNG'));
  if(whiteGroup && !whiteGroup[1].includes('kali63')) whiteGroup[1].unshift('kali63');
  const resultBox=(title,r)=>panel(title,`<div class="mode-result61"><div class="cards">${metric('Exit',r.exit_code??'—',r.ok?'green':'red')}${metric('Backend',r.backend||'Kali SSH')}</div><pre style="max-height:420px;overflow:auto;white-space:pre-wrap">${esc((r.stdout||'')+(r.stderr?'\n[stderr]\n'+r.stderr:''))}</pre></div>`);
  pages.kali63=async()=>{
    const admin=isAdmin(),runner=canWrite();
    let c={enabled:false};if(admin){try{c=await api('/v1/kali/config')}catch(e){}}
    const configBody=admin
      ? `<form id="kali63-form"><div class="form-grid">${input('IP/Hostname Kali','host','text',c.host||'')}${input('SSH port','port','number',c.port||22)}${input('Username','username','text',c.username||'kali')}${input('Password (để trống nếu đã lưu)','password','password','')}${input('SSH host key SHA256','hostkey_sha256','text',c.hostkey_sha256||'')}</div><label class="check"><input name="enabled" type="checkbox" ${c.enabled?'checked':''}> Bật Kali worker</label><div class="toolbar"><button type="button" id="kali63-probe">Lấy fingerprint</button><button class="primary" type="submit">Lưu cấu hình</button><button type="button" id="kali63-test">Kiểm tra kết nối</button><button type="button" id="kali63-tools">Kiểm tra tools</button></div></form><div id="kali63-config-result"></div>`
      : `<p class="caption">Chỉ Admin được xem/thay đổi cấu hình Kali.${runner?' Operator có thể kiểm tra kết nối và chạy tác vụ phòng thủ.':''}</p><div class="toolbar">${runner?'<button type="button" id="kali63-test">Kiểm tra kết nối</button>':''}<button type="button" id="kali63-tools">Kiểm tra tools</button></div><div id="kali63-config-result"></div>`;
    const runBody=runner
      ? `<form id="kali63-run"><div class="form-grid">${select('Profile','profile',['network_discovery','port_service_scan','tls_audit','web_headers','worker_network_state'],'network_discovery')}${input('Private IP/CIDR hoặc private URL','target','text','192.168.1.0/24')}${input('Port (TLS)','port','number',443)}</div><div class="toolbar"><button class="primary" type="submit">Chạy bằng Kali</button></div></form><div id="kali63-run-result"></div><p class="caption">Network discovery tối đa /20 (4096 địa chỉ). Port scan dùng TCP connect + top 100 ports. Không có exploit, brute-force, pivot, persistence hay flood.</p>`
      : `<p class="caption">Tài khoản ${esc(state.user?.role||'hiện tại')} chỉ có quyền xem. Chạy Kali yêu cầu Admin hoặc Operator.</p>`;
    return `<div class="mode-hero61 white"><div><div class="eyebrow">KALI LINUX WORKER</div><h2>Kali Linux Integration</h2><p>Kali làm execution worker cho các tác vụ phòng thủ cần công cụ Linux. Mục tiêu chủ động bị giới hạn ở private IP/CIDR; Red Team vẫn là mô phỏng lab.</p></div></div>`+
      panel('Kết nối Kali',configBody)+panel('Chạy tác vụ phòng thủ bằng Kali',runBody);
  };
  forms['kali63-form']=async f=>{const v=vals(f);const body={host:v.host,port:Number(v.port||22),username:v.username,password:v.password||null,hostkey_sha256:v.hostkey_sha256,enabled:!!f.elements.enabled.checked};const r=await api('/v1/kali/config',{method:'POST',body:JSON.stringify(body)});$('#kali63-config-result').innerHTML=panel('Đã lưu',kv(r));toast('Đã lưu Kali worker','ok');};
  forms['kali63-run']=async f=>{const v=vals(f);const out=$('#kali63-run-result');out.innerHTML='<div class="loading">Kali đang thực thi tác vụ…</div>';try{const r=await api('/v1/kali/run',{method:'POST',body:JSON.stringify({profile:v.profile,target:v.target,port:Number(v.port||443)})});out.innerHTML=resultBox('Kết quả Kali',r);}catch(e){out.innerHTML=panel('Lỗi',`<pre>${esc(e.message||String(e))}</pre>`);}};
  document.addEventListener('click',async e=>{
    if(e.target?.id==='kali63-probe'){const f=$('#kali63-form'),v=vals(f);try{const r=await api(`/v1/kali/probe-hostkey?host=${encodeURIComponent(v.host)}&port=${encodeURIComponent(v.port||22)}`);f.elements.hostkey_sha256.value=r.sha256;$('#kali63-config-result').innerHTML=panel('SSH fingerprint',kv(r));}catch(err){toast(err.message||String(err),'error');}}
    if(e.target?.id==='kali63-test'){try{const r=await api('/v1/kali/test',{method:'POST'});$('#kali63-config-result').innerHTML=resultBox('Kiểm tra kết nối',r);}catch(err){toast(err.message||String(err),'error');}}
    if(e.target?.id==='kali63-tools'){try{const r=await api('/v1/kali/tools');$('#kali63-config-result').innerHTML=resultBox('Kali tools',r);}catch(err){toast(err.message||String(err),'error');}}
  });

  // Attach Kali execution to the existing defensive pages that materially benefit from Linux tooling.
  const appendKali=(page,profile,label,targetHtml)=>{
    const old=pages[page]; if(typeof old!=='function') return;
    pages[page]=async()=>{const html=await old();if(!canWrite())return html;return html+panel('🐉 Kali Linux Worker',`<form id="kali63-${page}">${targetHtml}<input type="hidden" name="profile" value="${profile}"><div class="toolbar"><button class="primary" type="submit">${label}</button><button type="button" data-action="page" data-page="kali63">Cấu hình Kali</button></div></form><div id="kali63-${page}-result"></div><p class="caption">Tác vụ này chạy trên Kali qua SSH đã pin host key. Chỉ private IP/CIDR hoặc private URL được chấp nhận.</p>`);};
    forms[`kali63-${page}`]=async f=>{const v=vals(f),out=$(`#kali63-${page}-result`);out.innerHTML='<div class="loading">Kali đang thực thi…</div>';try{const r=await api('/v1/kali/run',{method:'POST',body:JSON.stringify({profile, target:v.target||v.network||v.asset_ip||v.url||'', port:Number(v.port||443)})});out.innerHTML=resultBox('Kết quả Kali',r);}catch(e){out.innerHTML=panel('Kali lỗi',`<pre>${esc(e.message||String(e))}</pre>`);}};
  };
  appendKali('scan','network_discovery','Quét discovery bằng Kali',input('Private IPv4 CIDR','target','text','192.168.1.0/24'));
  appendKali('vuln51','port_service_scan','Quét service bằng Kali',input('Private IP/hostname','target','text','192.168.1.1'));
  appendKali('bluetls62','tls_audit','Kiểm tra TLS bằng Kali',`${input('Private IP/hostname','target','text','192.168.1.1')}${input('Port','port','number',443)}`);
  appendKali('blueweb61','web_headers','Kiểm tra headers bằng Kali',input('Private URL','target','text','https://192.168.1.1/'));
  const oldGo=window.go;window.go=async function(page){const r=await oldGo(page);if(page==='kali63'){const b=$('#breadcrumb');if(b)b.textContent='🛡 HACKER MŨ TRẮNG · KALI WORKER';}return r;};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>navigation(),{once:true});else navigation();
  window.naKali63={version:'6.9.0-hotfix15',mode:'defensive-authorized-only',profiles:['network_discovery','port_service_scan','tls_audit','web_headers','worker_network_state']};
})();
