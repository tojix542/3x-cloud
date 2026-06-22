(function(){
  const field = document.querySelector('[data-pin-field]');
  const accept = document.querySelector('[data-accept]');
  const action = document.querySelector('[data-download-action]');
  const STORE = 'threex_admin_pins';
  function todayISO(){ return new Date().toISOString().slice(0,10); }
  function norm(v){ return String(v || '').replace(/[^A-Za-z0-9]/g,'').toUpperCase(); }
  function loadPins(){
    try{
      const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
      if(Array.isArray(saved)) return saved;
    }catch(e){}
    const defaults = window.THREEX_ADMIN_DEFAULT_PINS || [];
    localStorage.setItem(STORE, JSON.stringify(defaults));
    return defaults;
  }
  function savePins(pins){ localStorage.setItem(STORE, JSON.stringify(pins)); }
  function statusOf(p){
    if(p.expires && p.expires < todayISO()) return 'expired';
    if(Number(p.uses||0) >= Number(p.maxUses||1)) return 'used';
    return p.status || 'active';
  }
  function update(){
    const ready = accept?.checked && norm(field?.value).length >= 6;
    if(action) action.disabled = !ready;
  }
  field?.addEventListener('input',()=>{ field.value = field.value.toUpperCase(); update(); });
  accept?.addEventListener('change', update);
  action?.addEventListener('click',()=>{
    if(action.disabled) return;
    const entered = norm(field.value);
    let pins = loadPins();
    const index = pins.findIndex(p => norm(p.pin) === entered);
    if(index === -1){ window.toast?.('Invalid PIN. Please generate a new PIN from the PIN Generator.'); return; }
    const p = pins[index];
    const status = statusOf(p);
    if(status !== 'active'){ window.toast?.(`PIN is ${status}. Create a fresh one in Admin.`); return; }
    pins[index] = {...p, uses:Number(p.uses||0)+1, lastUsed:new Date().toISOString()};
    savePins(pins);
    window.toast?.('PIN accepted. Starting download simulation...');
    setTimeout(()=>{
      location.href = 'scan-simulation.html';
    }, 800);
  });
  update();
})();