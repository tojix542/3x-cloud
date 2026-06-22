(function(){
  const STORE = 'threex_admin_pins';
  let pins = [];
  try{
    const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
    pins = Array.isArray(saved) ? saved : (window.THREEX_ADMIN_DEFAULT_PINS || []);
  }catch(e){ pins = window.THREEX_ADMIN_DEFAULT_PINS || []; }

  function todayISO(){ return new Date().toISOString().slice(0,10); }
  function statusOf(p){
    if(p.expires && p.expires < todayISO()) return 'expired';
    if(Number(p.uses||0) >= Number(p.maxUses||1)) return 'used';
    return p.status || 'active';
  }
  function save(){ localStorage.setItem(STORE, JSON.stringify(pins)); render(); }
  function render(){
    const tbody = document.querySelector('[data-pin-table]');
    if(!tbody) return;
    const filter = document.querySelector('[data-pin-filter].active')?.dataset.pinFilter || 'all';
    const rows = pins.filter(p => filter === 'all' || statusOf(p) === filter).map((p,i) => {
      const st = statusOf(p);
      return `<tr>
        <td><strong class="mono">${p.pin}</strong></td>
        <td>${p.plan}<br><span class="dim">${p.owner}</span></td>
        <td><span class="badge badge-${st==='active'?'info':st==='used'?'clean':'suspicious'}">${st.toUpperCase()}</span></td>
        <td>${p.uses||0}/${p.maxUses||1}</td>
        <td><span class="dim">${p.created}</span><br><span class="dim">→ ${p.expires}</span></td>
        <td><div class="table-actions"><button class="btn btn-sm btn-secondary" onclick="copyPin('${p.pin}')">Copy</button><button class="btn btn-sm btn-danger" onclick="deletePin(${i})">Delete</button></div></td>
      </tr>`;
    }).join('');
    tbody.innerHTML = rows || '<tr><td colspan="6" style="text-align:center;color:var(--muted)">No PINs</td></tr>';

    document.querySelector('[data-pin-total]') && (document.querySelector('[data-pin-total]').textContent = pins.length);
    document.querySelector('[data-pin-active]') && (document.querySelector('[data-pin-active]').textContent = pins.filter(p=>statusOf(p)==='active').length);
    document.querySelector('[data-pin-used]') && (document.querySelector('[data-pin-used]').textContent = pins.filter(p=>statusOf(p)==='used').length);
    document.querySelector('[data-pin-expired]') && (document.querySelector('[data-pin-expired]').textContent = pins.filter(p=>statusOf(p)==='expired').length);
  }

  window.copyPin = function(pin){ navigator.clipboard?.writeText(pin); window.toast?.('Copied: '+pin); };
  window.deletePin = function(idx){ pins.splice(idx,1); save(); window.toast?.('PIN deleted'); };

  document.querySelectorAll('[data-pin-filter]').forEach(btn=>{
    btn.addEventListener('click',()=>{
      document.querySelectorAll('[data-pin-filter]').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      render();
    });
  });

  const form = document.querySelector('[data-pin-form]');
  if(form){
    form.addEventListener('submit',e=>{
      e.preventDefault();
      const fd = new FormData(form);
      const type = fd.get('type') || 'six';
      const amount = parseInt(fd.get('amount')||1);
      const duration = parseInt(fd.get('duration')||7);
      const plan = fd.get('plan') || 'Weekly';
      const product = fd.get('product') || '3X Client';
      const owner = fd.get('owner') || 'Customer';
      const note = fd.get('note') || '';
      const maxUses = parseInt(fd.get('maxUses')||1);
      const created = todayISO();
      const expires = new Date(Date.now()+duration*864e5).toISOString().slice(0,10);
      const out = document.querySelector('[data-generated-output]');
      let generated = [];
      for(let i=0;i<amount;i++){
        let pin;
        if(type==='six') pin = Math.floor(100000+Math.random()*900000).toString();
        else if(type==='four') pin = Math.random().toString(36).slice(2,6).toUpperCase();
        else pin = Math.floor(10000000+Math.random()*90000000).toString();
        const p = {pin, product, plan, owner, note, status:'active', uses:0, maxUses, created, expires};
        pins.push(p); generated.push(p);
      }
      save();
      if(out){
        out.innerHTML = generated.map(p=>`<div class="generated-pin"><span class="mono" style="font-size:16px;font-weight:700">${p.pin}</span><span class="dim">${p.plan} · ${p.owner}</span></div>`).join('');
      }
      window.toast?.(`Generated ${amount} PIN(s)`);
    });
  }

  document.querySelector('[data-clear-pins]')?.addEventListener('click',()=>{
    pins = [];
    save();
    window.toast?.('PIN inventory cleared');
  });

  document.querySelector('[data-reset-pins]')?.addEventListener('click',()=>{
    pins = JSON.parse(JSON.stringify(window.THREEX_ADMIN_DEFAULT_PINS || []));
    save();
    window.toast?.('Default data restored');
  });

  document.querySelector('[data-export-pins]')?.addEventListener('click',()=>{
    const csv = ['PIN,Product,Plan,Owner,Status,Uses,MaxUses,Created,Expires'].concat(pins.map(p=>`${p.pin},${p.product},${p.plan},${p.owner},${statusOf(p)},${p.uses||0},${p.maxUses||1},${p.created},${p.expires}`)).join('\n');
    const blob = new Blob([csv],{type:'text/csv'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = '3x-pins.csv'; a.click();
    URL.revokeObjectURL(url);
    window.toast?.('CSV exported');
  });

  const licenseTable = document.querySelector('[data-license-table]');
  if(licenseTable){
    const licenses = window.THREEX_LICENSES || [];
    licenseTable.innerHTML = licenses.map(l=>`<tr>
      <td class="mono">${l.key}</td>
      <td>${l.owner}</td>
      <td>${l.seats}</td>
      <td><span class="badge badge-${l.hwid==='Bound'?'info':'suspicious'}">${l.hwid}</span></td>
      <td><span class="badge badge-${l.status==='active'?'clean':'suspicious'}">${l.status.toUpperCase()}</span></td>
      <td>${l.renewal}</td>
    </tr>`).join('');
  }

  const userTable = document.querySelector('[data-user-table]');
  if(userTable){
    const users = window.THREEX_USERS || [];
    userTable.innerHTML = users.map(u=>`<tr>
      <td><strong>${u.name}</strong><br><span class="dim mono">${u.discord}</span></td>
      <td><span class="badge badge-info">${u.role}</span></td>
      <td>${u.scans}</td>
      <td><span class="dim">${u.lastSeen}</span></td>
    </tr>`).join('');
  }

  render();
})();