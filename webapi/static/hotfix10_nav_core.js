'use strict';
/* Hotfix15: final core navigation verifier + release branding. */
(()=>{
  const desired=[
    ['TỔNG QUAN',['dashboard','daily57','soc51','taskcenter47']],
    ['🛡 HACKER MŨ TRẮNG · PHÒNG THỦ',['bluehub61','kali63','scan','ipmac','vuln51','bluetls62','blueids62','blueweb61','blueapi62','bluesecrets62','bluelog61','bluemalware62','bluepass61','bluefirewall62','blueiam62','blueir62','bluecontainer62','bluefim62','blueedr62','bluephish62','siem51','threat54','endpoint58','secpost51']],
    ['🥷 HACKER MŨ ĐEN · RED TEAM LAB',['redhub61','redinject61','redxss61','redidor61','redupload62','redredirect62','redssrf62','redxxe62','redauth61','redpacket61','redload61','redhash62','redsupply62','redsession62','redmitm62','redtunnel62','redprivesc62','redpersist62','redevasion62']],
    ['THIẾT BỊ & HẠ TẦNG',['devices','managed','profiles','organization','topology','lan','netspeed59','pingmonitor','history','monitoringx','health','server','snmp','extensions','remote']],
    ['VẬN HÀNH & PHẢN ỨNG',['autoip','audit','terminal','backup','compare','dailyaudit','scheduler','restore','readiness','jobs','compliance53','notify56','reports','cases55','security','alerts','rules','incidents','services','sla','inbox47']],
    ['QUẢN TRỊ',['accounts','credentials','vault51','crypto51','production','runtime47','system46','platform50','auditall','parity','notify','logs','diag','settingsx','password']]
  ];
  function apply(){
    try{
      groups.splice(0,groups.length,...desired);
      state.groupOpen={0:true,1:true,2:true,3:false,4:false,5:false};
      if(typeof navigation==='function') navigation();
      const sub=document.querySelector('.brand small');
      if(sub) sub.textContent='Cybersecurity Platform / UI 6.9.0 · HF15';
      document.documentElement.dataset.naUiBuild='6.9.0-hf15';
    }catch(e){console.error('HF15_NAV_CORE',e);}
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',apply,{once:true}); else apply();
  window.addEventListener('load',apply,{once:true});
  setTimeout(apply,250);
  window.naHotfix10={version:'6.9.0-hotfix15',navigation:'core-authoritative'}; window.naHotfix14={version:'6.9.0-hotfix14',scope:'full-qa-fix'}; window.naHotfix15={version:'6.9.0-hotfix15',scope:'scheduler-api-stability'};
})();
