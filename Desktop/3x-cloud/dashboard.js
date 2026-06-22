(function(){
  const scans = window.THREEX_SCANS || [];
  const defaults = window.THREEX_ADMIN_DEFAULT_PINS || [];
  let pins = defaults;
  try{
    const saved = JSON.parse(localStorage.getItem('threex_admin_pins') || 'null');
    if(Array.isArray(saved)) pins = saved;
  }catch(e){}
  const today = new Date().toISOString().slice(0,10);
  const statusOfPin = p => (p.expires && p.expires < today) ? 'expired' : Number(p.uses||0) >= Number(p.maxUses||1) ? 'used' : (p.status || 'active');
  const count = type => scans.filter(s=>s.status===type).length;
  const set = (sel, value) => { const el = document.querySelector(sel); if(el) el.textContent = value; };
  const avg = scans.length ? Math.round(scans.reduce((sum,s)=>sum+Number(s.score||0),0)/scans.length) : 0;
  set('[data-total-scans]', scans.length);
  set('[data-clean-scans]', count('clean'));
  set('[data-suspicious-scans]', count('suspicious'));
  set('[data-threat-scans]', count('threat'));
  set('[data-average-score]', `${avg}%`);
  set('[data-active-pins]', pins.filter(p=>statusOfPin(p)==='active').length);
  set('[data-pin-active-small]', pins.filter(p=>statusOfPin(p)==='active').length);
  set('[data-pin-used-small]', pins.filter(p=>statusOfPin(p)==='used').length);
  set('[data-pin-expired-small]', pins.filter(p=>statusOfPin(p)==='expired').length);

  const latest = scans.slice(0,6);
  const table = document.querySelector('[data-recent-scans]');
  if(table){
    table.innerHTML = latest.map(s=>`<tr>
      <td><strong>${s.id}</strong><br><span class="dim">PIN ${s.pin}</span></td>
      <td>${s.player}<br><span class="dim">${s.discord}</span></td>
      <td><span class="mono" style="font-size:11px">${s.hwid ? s.hwid.slice(0,16)+'...' : 'N/A'}</span></td>
      <td>${badge(s.status)}</td>
      <td>${s.score}%</td>
      <td>${s.created}</td>
      <td><a class="btn btn-secondary btn-sm" href="scan-report.html?id=${s.id}">Open</a></td>
    </tr>`).join('');
  }

  const bars = document.querySelector('[data-status-bars]');
  if(bars){
    const items = [
      ['clean','Clean',count('clean')],
      ['suspicious','Suspicious',count('suspicious')],
      ['threat','Threat',count('threat')]
    ];
    bars.innerHTML = items.map(([key,label,value]) => {
      const pct = scans.length ? Math.round(value/scans.length*100) : 0;
      return `<div class="status-bar"><div><strong>${label}</strong><span>${value} reports</span></div><div class="bar"><i class="bar-${key}" style="width:${pct}%"></i></div><b>${pct}%</b></div>`;
    }).join('');
  }

  const games = {};
  scans.forEach(s => games[s.game] = (games[s.game] || 0) + 1);
  const gameList = document.querySelector('[data-game-list]');
  if(gameList){
    gameList.innerHTML = Object.entries(games).sort((a,b)=>b[1]-a[1]).map(([game,total]) => `<div class="mini-row"><span>${game}</span><strong>${total}</strong></div>`).join('');
  }

  const feed = document.querySelector('[data-event-feed]');
  const events = window.THREEX_EVENTS || [];
  if(feed){
    feed.innerHTML = events.map(ev => `<div class="timeline-item"><span class="mono">${ev.time}</span><div><strong>${ev.title}</strong><p>${ev.detail}</p></div></div>`).join('');
  }

  function badge(status){
    const label = status === 'clean' ? 'Clean' : status === 'threat' ? 'Threat' : 'Suspicious';
    return `<span class="badge badge-${status}">${label}</span>`;
  }
})();