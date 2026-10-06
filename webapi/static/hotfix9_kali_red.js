'use strict';
/* 6.9.0 Hotfix15: authoritative White/Red navigation + safe Kali-backed Red-Team lab checks. */
(()=>{
  const whitePages=['bluehub61','kali63','scan','ipmac','vuln51','bluetls62','blueids62','blueweb61','blueapi62','bluesecrets62','bluelog61','bluemalware62','bluepass61','bluefirewall62','blueiam62','blueir62','bluecontainer62','bluefim62','blueedr62','bluephish62','siem51','threat54','endpoint58','secpost51'];
  const redPages=['redhub61','redinject61','redxss61','redidor61','redupload62','redredirect62','redssrf62','redxxe62','redauth61','redpacket61','redload61','redhash62','redsupply62','redsession62','redmitm62','redtunnel62','redprivesc62','redpersist62','redevasion62'];
  const overview=['dashboard','daily57','soc51','taskcenter47'];
  const infra=['devices','managed','profiles','organization','topology','lan','netspeed59','pingmonitor','history','monitoringx','health','server','snmp','extensions','remote'];
  const ops=['autoip','audit','terminal','backup','compare','dailyaudit','scheduler','restore','readiness','jobs','compliance53','notify56','reports','cases55','security','alerts','rules','incidents','services','sla','inbox47'];
  const admin=['accounts','credentials','vault51','crypto51','production','runtime47','system46','platform50','auditall','parity','notify','logs','diag','settingsx','password'];

  function installGroups(){
    groups.splice(0,groups.length,
      ['TỔNG QUAN',overview],
      ['🛡 HACKER MŨ TRẮNG · PHÒNG THỦ',whitePages],
      ['🥷 HACKER MŨ ĐEN · RED TEAM LAB',redPages],
      ['THIẾT BỊ & HẠ TẦNG',infra],
      ['VẬN HÀNH & PHẢN ỨNG',ops],
      ['QUẢN TRỊ',admin]
    );
    state.groupOpen={0:true,1:true,2:true,3:false,4:false,5:false};
    if(typeof navigation==='function') navigation();
  }

  // Always install after all legacy navigation patches have executed.
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',installGroups,{once:true});
  else installGroups();
  window.addEventListener('load',installGroups,{once:true});

  const resultBox=(title,r)=>panel(title,`<div class="mode-result61"><div class="cards">${metric('Exit',r.exit_code??'—',r.ok?'green':'red')}${metric('Backend',r.backend||'Kali SSH')}</div><pre style="max-height:420px;overflow:auto;white-space:pre-wrap">${esc((r.stdout||'')+(r.stderr?'\n[stderr]\n'+r.stderr:''))}</pre></div>`);
  function attach(page,profile,label,controls,note){
    const old=pages[page]; if(typeof old!=='function') return;
    pages[page]=async()=>{
      const html=await old();
      if(!canWrite())return html;
      return html+panel('🐉 Kali Linux · Kiểm thử được ủy quyền',`<form id="hf9-${page}">${controls}<div class="toolbar"><button class="primary" type="submit">${esc(label)}</button><button type="button" data-action="page" data-page="kali63">Cấu hình Kali</button></div></form><div id="hf9-${page}-result"></div><p class="caption">${esc(note)}</p>`);
    };
    forms[`hf9-${page}`]=async f=>{
      const v=vals(f),out=$(`#hf9-${page}-result`);out.innerHTML='<div class="loading">Kali đang kiểm tra…</div>';
      try{const r=await api('/v1/kali/run',{method:'POST',body:JSON.stringify({profile,target:v.target||'',port:Number(v.port||443)})});out.innerHTML=resultBox('Kết quả Kali',r)}
      catch(e){out.innerHTML=panel('Kali lỗi',`<pre>${esc(e.message||String(e))}</pre>`)}
    };
  }

  // Safe Red-Team integrations: defensive observation only, private targets only.
  attach('redsession62','session_cookie_audit','Kiểm tra cookie/session bằng Kali',input('Private URL','target','text','https://192.168.1.1/'),'Chỉ đọc response headers để đánh giá Secure/HttpOnly/SameSite; không chiếm hoặc tái sử dụng session.');
  attach('redmitm62','tls_transport_audit','Kiểm tra TLS transport bằng Kali',`${input('Private IP/hostname','target','text','192.168.1.1')}${input('Port','port','number',443)}`,'Chỉ kiểm tra TLS/certificate; không ARP spoof, không chặn hay sửa lưu lượng.');
  attach('redsupply62','component_versions','Kiểm kê phiên bản tool trên Kali',input('Không cần mục tiêu','target','text','worker-local'),'Chỉ inventory phiên bản trên Kali worker để phục vụ patch/CVE review; không khai thác dependency.');
  attach('redload61','http_capacity_probe','Chạy capacity probe giới hạn',input('Private URL','target','text','http://192.168.1.1/'),'Tối đa 10 request tuần tự, nghỉ 200 ms giữa request; không concurrency, không flood/DDoS.');

  // Packet lab can use Kali worker state as context, but does not sniff interfaces.
  const oldPacket=pages.redpacket61;
  if(typeof oldPacket==='function'){
    pages.redpacket61=async()=>{const html=await oldPacket();if(!canWrite())return html;return html+panel('🐉 Kali worker · Trạng thái mạng',`<form id="hf9-redpacket61"><div class="toolbar"><button class="primary" type="submit">Xem interface/route/socket của Kali</button><button type="button" data-action="page" data-page="kali63">Cấu hình Kali</button></div></form><div id="hf9-redpacket61-result"></div><p class="caption">Không bật tcpdump/tshark capture. Chỉ đọc trạng thái interface, route và socket của chính Kali worker.</p>`)};
    forms['hf9-redpacket61']=async f=>{const out=$('#hf9-redpacket61-result');out.innerHTML='<div class="loading">Kali đang kiểm tra…</div>';try{const r=await api('/v1/kali/run',{method:'POST',body:JSON.stringify({profile:'worker_network_state'})});out.innerHTML=resultBox('Kali network state',r)}catch(e){out.innerHTML=panel('Kali lỗi',`<pre>${esc(e.message||String(e))}</pre>`)}};
  }

  window.naHotfix9={version:'6.9.0-hotfix15',navigation:'authoritative',kaliRedProfiles:['session_cookie_audit','tls_transport_audit','component_versions','http_capacity_probe','worker_network_state']};
})();
