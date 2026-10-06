/* NetworkAutomation Cybersecurity UI 6.9.0 Hotfix15 - self-heal UI/UX polish; presentation only. */
(()=>{
  const drawerWords=/chi tiết|details|kết quả|lịch sử|history|evidence|thông tin|profile|telemetry|certificate|cấu hình/i;
  const uiGroups=[['TỔNG QUAN',['dashboard','daily57','soc51','taskcenter47']],['🛡 HACKER MŨ TRẮNG · PHÒNG THỦ',['bluehub61','kali63','scan','ipmac','vuln51','bluetls62','blueids62','blueweb61','blueapi62','bluesecrets62','bluelog61','bluemalware62','bluepass61','bluefirewall62','blueiam62','blueir62','bluecontainer62','bluefim62','blueedr62','bluephish62','siem51','threat54','endpoint58','secpost51']],['🥷 HACKER MŨ ĐEN · RED TEAM LAB',['redhub61','redinject61','redxss61','redidor61','redupload62','redredirect62','redssrf62','redxxe62','redauth61','redpacket61','redload61','redhash62','redsupply62','redsession62','redmitm62','redtunnel62','redprivesc62','redpersist62','redevasion62']],['THIẾT BỊ & HẠ TẦNG',['devices','managed','profiles','organization','topology','lan','netspeed59','pingmonitor','history','monitoringx','health','server','snmp','extensions','remote']],['VẬN HÀNH & PHẢN ỨNG',['autoip','audit','terminal','backup','compare','dailyaudit','scheduler','restore','readiness','jobs','compliance53','notify56','reports','cases55','security','alerts','rules','incidents','services','sla','inbox47']],['QUẢN TRỊ',['accounts','credentials','vault51','crypto51','production','runtime47','system46','platform50','auditall','parity','notify','logs','diag','settingsx','password']]];
  const groupByPage=()=>{for(const [label,list] of uiGroups){if(list.includes(state.page))return label}return 'OPERATIONS CENTER'};
  function enhanceTables(root=document){
    root.querySelectorAll('table').forEach(t=>{
      t.classList.add('ui600-mobile-table');
      const heads=[...t.querySelectorAll('thead th')].map(x=>x.textContent.trim());
      t.querySelectorAll('tbody tr').forEach(tr=>[...tr.children].forEach((td,i)=>{if(!td.dataset.label)td.dataset.label=heads[i]||'Thông tin'}));
    });
  }
  function enhancePage(){
    document.body.classList.add('ui600');
    const group=groupByPage();
    const bc=document.querySelector('#breadcrumb');if(bc)bc.textContent=group;
    const brand=document.querySelector('.brand small');if(brand){brand.textContent='Cybersecurity Platform / UI 6.9.0';brand.classList.add('ui600-version')}
    const content=document.querySelector('#content');if(content){content.dataset.page=state.page||'';enhanceTables(content)}
  }
  function installQuickActions(){
    const hr=document.querySelector('.header-right');if(!hr||hr.querySelector('.ui600-quick'))return;
    const q=document.createElement('div');q.className='ui600-quick';
    q.innerHTML='<button type="button" data-action="page" data-page="daily57">Hôm nay</button><button type="button" data-action="page" data-page="siem51" class="critical">Cảnh báo</button><button type="button" data-action="page" data-page="netspeed59">Đường truyền</button><button type="button" data-action="page" data-page="platform50">Hệ thống</button>';
    hr.insertBefore(q,hr.firstChild);
  }
  const originalGo=window.go;
  if(typeof originalGo==='function')window.go=async function(p){const r=await originalGo(p);enhancePage();return r};
  const originalModal=window.modal;
  if(typeof originalModal==='function')window.modal=function(title,body){const r=originalModal(title,body);const d=document.querySelector('#dialog');if(d){d.classList.toggle('ui600-drawer',drawerWords.test(String(title||'')));enhanceTables(d)}return r};
  const observer=new MutationObserver(muts=>{for(const m of muts){if(m.type==='childList'){enhanceTables(m.target instanceof Element?m.target:document);break}}});
  const initEnterprise600=()=>{
    document.body.classList.add('ui600');installQuickActions();enhancePage();
    const content=document.querySelector('#content');if(content)observer.observe(content,{subtree:true,childList:true});
    const dialog=document.querySelector('#dialog');if(dialog)observer.observe(dialog,{subtree:true,childList:true});
  };
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initEnterprise600,{once:true});else initEnterprise600();
  window.naEnterprise600={version:'6.9.0-hf15',features:['responsive-tables','detail-drawers','sticky-tables','quick-actions','a11y-focus','final-polish','system-health-quick-action']};
})();
