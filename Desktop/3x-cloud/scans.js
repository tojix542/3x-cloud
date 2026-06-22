(function(){
  const scans = window.THREEX_SCANS || [];
  const grid = document.querySelector('[data-scan-grid]');
  const table = document.querySelector('[data-scan-table]');
  const search = document.querySelector('[data-search]');
  const statusFilter = document.querySelector('[data-status-filter]');
  const gameFilter = document.querySelector('[data-game-filter]');

  function badge(status){
    const label = status === 'clean' ? 'Clean' : status === 'threat' ? 'Threat' : 'Suspicious';
    return `<span class="badge badge-${status}">${label}</span>`;
  }

  function render(){
    const q = (search?.value || '').toLowerCase();
    const st = statusFilter?.value || 'all';
    const gm = gameFilter?.value || 'all';
    const filtered = scans.filter(s=>{
      const matchesQ = !q || s.player.toLowerCase().includes(q) || s.discord.toLowerCase().includes(q) || s.id.toLowerCase().includes(q) || s.pin.includes(q);
      const matchesSt = st === 'all' || s.status === st;
      const matchesGm = gm === 'all' || s.game === gm;
      return matchesQ && matchesSt && matchesGm;
    });

    if(grid){
      grid.innerHTML = filtered.slice(0,9).map(s=>`<article class="scan-card reveal">
        <div class="scan-card-top"><h3>${s.player}</h3>${badge(s.status)}</div>
        <p class="dim">${s.discord} · ${s.game}</p>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px">
          <span class="dim mono" style="font-size:12px">${s.id}</span>
          <a class="btn btn-secondary btn-sm" href="scan-report.html?id=${s.id}">Open</a>
        </div>
      </article>`).join('');
    }

    if(table){
      table.innerHTML = filtered.map(s=>`<tr>
        <td class="mono">${s.id}</td>
        <td><strong>${s.player}</strong></td>
        <td>${s.discord}</td>
        <td>${badge(s.status)}</td>
        <td><span class="dim">${s.created}</span></td>
        <td><a class="btn btn-secondary btn-sm" href="scan-report.html?id=${s.id}">Open</a></td>
      </tr>`).join('');
    }
  }

  search?.addEventListener('input', render);
  statusFilter?.addEventListener('change', render);
  gameFilter?.addEventListener('change', render);
  render();
})();