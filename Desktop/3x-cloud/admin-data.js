window.THREEX_ADMIN_DEFAULT_PINS = [
  {pin:'123456', product:'3X Client', plan:'Demo', owner:'Staff Access', note:'Default test PIN', status:'active', uses:0, maxUses:100, created:'2026-06-22', expires:'2026-07-22'},
  {pin:'842190', product:'3X Client', plan:'Weekly', owner:'Ares Team', note:'Team delivery batch', status:'active', uses:4, maxUses:10, created:'2026-06-22', expires:'2026-06-29'},
  {pin:'901338', product:'3X Client', plan:'Monthly', owner:'Nova Staff', note:'Customer replacement PIN', status:'used', uses:1, maxUses:1, created:'2026-06-21', expires:'2026-07-21'},
  {pin:'778214', product:'3X Cloud Access', plan:'Trial', owner:'Senior Analyst', note:'Expired sample', status:'expired', uses:1, maxUses:5, created:'2026-06-10', expires:'2026-06-17'}
];

window.THREEX_LICENSES = [
  {key:'3X-PRO-82KQ-77LM', owner:'Ares Team', plan:'Team Pro', seats:'6 / 10', hwid:'Bound', status:'active', renewal:'2026-07-22'},
  {key:'3X-MONTH-F4R9-XZ21', owner:'Nova Staff', plan:'Monthly', seats:'1 / 1', hwid:'Bound', status:'active', renewal:'2026-07-06'},
  {key:'3X-TRIAL-LL29-QW88', owner:'Pulse QA', plan:'Trial', seats:'0 / 1', hwid:'Reset', status:'paused', renewal:'2026-06-25'}
];

window.THREEX_USERS = [
  {name:'Senior Analyst', discord:'DISCORD-31012006', role:'Owner', scans:42, lastSeen:'Today'},
  {name:'Ares', discord:'DISCORD-88204412', role:'Senior Analyst', scans:27, lastSeen:'Today'},
  {name:'Zephyr', discord:'DISCORD-55190240', role:'Reviewer', scans:18, lastSeen:'Yesterday'},
  {name:'Pulse', discord:'DISCORD-77102004', role:'Support', scans:9, lastSeen:'2 days ago'}
];

window.THREEX_EVENTS = [
  {time:'14:51', title:'PIN generated', detail:'Weekly batch for Ares Team'},
  {time:'14:41', title:'Scan completed', detail:'3X-8721 marked Clean'},
  {time:'13:30', title:'Manual review', detail:'3X-8718 sent to senior analyst'},
  {time:'11:10', title:'License checked', detail:'Team Pro license verified'}
];

window.THREEX_DETECTION_STATS = {
  totalCheats: 214,
  totalSignatures: 704,
  totalMemoryAddresses: 163,
  totalFiles: 412,
  totalTimestamps: 1126,
  totalHashes: 136,
  sources: {dps: 1281, pca: 234, explorer: 467},
  topThreats: ['RedEngine','Eulen','Skript','Gosth','Susano','Keyser','HX','TZ','Degeo','Asgard'],
  services: ['DPS','PCA','Explorer']
};