(function(){
  const params = new URLSearchParams(location.search);
  const id = params.get('id') || '3X-8721';
  const scans = window.THREEX_SCANS || [];
  const scan = scans.find(s=>s.id===id) || scans[0];
  if(!scan) return;

  const set = (sel,val)=>{const el=document.querySelector(sel); if(el) el.textContent=val||'N/A';};

  set('[data-r-id]', scan.id);
  set('[data-r-player]', scan.player);
  set('[data-r-discord]', scan.discord);
  set('[data-r-discord-id]', scan.discordId);
  set('[data-r-fivem]', scan.fivemLicense);
  set('[data-r-rockstar]', scan.rockstarId);
  set('[data-r-license]', scan.license);
  set('[data-r-license2]', scan.license2);
  set('[data-r-steam]', scan.steamId);
  set('[data-r-hwid]', scan.hwid);
  set('[data-r-ip]', scan.ip);
  set('[data-r-game]', scan.game);
  set('[data-r-analyst]', scan.analyst);
  set('[data-r-date]', scan.created);
  set('[data-r-score]', scan.score);
  set('[data-r-duration]', scan.duration);
  set('[data-r-pin]', scan.pin);

  // Set previous scans count
  set('[data-previous-scans]', scan.previousScans || 0);
  set('[data-history-status]', scan.historyStatus || 'N/A');

  const historySummary = document.querySelector('[data-history-summary]');
  if(historySummary) historySummary.textContent = scan.historySummary || 'No previous scan history available.';

  const badge = document.querySelector('[data-r-status]');
  if(badge){
    badge.className = `badge badge-${scan.status}`;
    badge.textContent = scan.status === 'clean' ? 'CLEAN' : scan.status === 'threat' ? 'THREAT' : 'SUSPICIOUS';
  }

  const resultIcon = document.querySelector('[data-result-icon]');
  if(resultIcon){
    resultIcon.className = 'result-icon ' + scan.status;
    resultIcon.textContent = scan.status === 'clean' ? '✓' : scan.status === 'threat' ? '✕' : '!';
  }

  const resultHeading = document.querySelector('[data-result-heading]');
  if(resultHeading){
    resultHeading.textContent = scan.status === 'clean' ? 'CLEAN — NO ANOMALIES DETECTED' : 
                               scan.status === 'threat' ? 'THREAT — ACTION REQUIRED' : 
                               'SUSPICIOUS — MANUAL REVIEW NEEDED';
  }

  const verdict = document.querySelector('[data-cheating-verdict]');
  if(verdict){
    verdict.className = 'cheating-verdict ' + scan.status;
    const h3 = verdict.querySelector('h3');
    const p = verdict.querySelector('p');
    if(h3) h3.textContent = scan.status === 'clean' ? '✓ Player is CLEAN' : 
                            scan.status === 'threat' ? '✕ Player is CHEATING' : 
                            '! Player is SUSPICIOUS';
    if(p) p.textContent = scan.status === 'clean' ? 'No cheating indicators detected. All forensic checks passed successfully.' : 
                          scan.status === 'threat' ? 'Multiple cheating indicators detected. Immediate action recommended.' : 
                          'Some indicators require manual review by a senior analyst.';
  }

  // Render past detections
  const pastDetectionsContainer = document.querySelector('[data-past-detections]');
  if(pastDetectionsContainer && scan.pastDetections && scan.pastDetections.length > 0){
    pastDetectionsContainer.style.display = 'block';
    const pastList = document.querySelector('[data-past-detections-list]');
    if(pastList){
      pastList.innerHTML = scan.pastDetections.map(det => `
        <div style="margin-bottom:12px;padding:14px;border:1px solid rgba(239,68,68,.2);border-radius:12px;background:rgba(239,68,68,.04);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <strong style="font-size:14px;color:var(--danger);">${det.scanId}</strong>
            <span class="badge badge-${det.status === 'banned' ? 'threat' : det.status === 'threat' ? 'threat' : 'suspicious'}" style="font-size:11px">${det.status.toUpperCase()}</span>
          </div>
          <span style="font-size:12px;color:var(--muted);display:block;margin-bottom:6px;">Date: ${det.date}</span>
          <div style="font-size:13px;color:var(--text);">
            ${det.findings.map(f => `<div style="margin:4px 0;padding:6px 10px;background:rgba(0,0,0,.3);border-radius:8px;font-size:12px;">• ${f}</div>`).join('')}
          </div>
        </div>
      `).join('');
    }
  }

  // Check player history database
  const playerHistory = window.THREEX_PLAYER_HISTORY || {};
  const history = playerHistory[scan.discordId] || playerHistory[scan.fivemLicense?.replace('fivem:','')] || 
                  playerHistory[scan.steamId] || playerHistory[scan.hwid];

  const historyAlert = document.querySelector('[data-history-alert]');
  if(historyAlert && history){
    historyAlert.style.display = 'block';
    const historyAlertContent = document.querySelector('[data-history-alert-content]');
    if(historyAlertContent){
      historyAlertContent.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <strong style="font-size:16px;color:var(--danger);">⚠ PLAYER HISTORY ALERT</strong>
          <span class="badge badge-${history.status === 'REPEAT_OFFENDER' ? 'threat' : history.status === 'MONITORING' ? 'suspicious' : 'info'}" style="font-size:11px">${history.status}</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;">
          <div style="text-align:center;padding:10px;background:rgba(0,0,0,.2);border-radius:10px;">
            <span style="font-size:11px;color:var(--muted);display:block;">Total Scans</span>
            <strong style="font-size:20px;color:var(--text);">${history.totalScans}</strong>
          </div>
          <div style="text-align:center;padding:10px;background:rgba(239,68,68,.1);border-radius:10px;">
            <span style="font-size:11px;color:var(--muted);display:block;">Threat</span>
            <strong style="font-size:20px;color:var(--danger);">${history.threatScans}</strong>
          </div>
          <div style="text-align:center;padding:10px;background:rgba(245,158,11,.1);border-radius:10px;">
            <span style="font-size:11px;color:var(--muted);display:block;">Suspicious</span>
            <strong style="font-size:20px;color:var(--warn);">${history.suspiciousScans}</strong>
          </div>
        </div>
        <p style="font-size:13px;color:var(--muted);margin:0;">${history.notes}</p>
      `;
    }
  }

  const cheatCheck = scan.cheatServerCheck;
  if(cheatCheck){
    set('[data-cheat-checked]', cheatCheck.checked);
    set('[data-cheat-found]', cheatCheck.foundIn);
    set('[data-cheat-risk]', cheatCheck.riskScore);

    const cheatBar = document.querySelector('[data-cheat-bar]');
    if(cheatBar){
      cheatBar.style.width = Math.min(cheatCheck.riskScore, 100) + '%';
      cheatBar.className = cheatCheck.riskScore >= 70 ? 'cheat-bar-fill threat' : 
                           cheatCheck.riskScore >= 30 ? 'cheat-bar-fill suspicious' : 
                           'cheat-bar-fill clean';
    }

    const cheatList = document.querySelector('[data-cheat-servers]');
    if(cheatList){
      if(cheatCheck.servers && cheatCheck.servers.length > 0){
        cheatList.innerHTML = cheatCheck.servers.map(s => `
          <div class="cheat-server-item">
            <div>
              <strong>${s.name}</strong>
              <span class="dim mono">${s.id}</span>
              <span style="font-size:12px;color:var(--muted);margin-top:2px;display:block;">Role: <span style="color:var(--text)">${s.role}</span> · Nick: ${s.nickname} · Joined: ${s.joined}</span>
            </div>
            <span class="badge badge-${s.riskWeight >= 70 ? 'threat' : s.riskWeight >= 40 ? 'suspicious' : 'info'}" style="font-size:11px">Risk ${s.riskWeight}</span>
          </div>
        `).join('');
      } else {
        cheatList.innerHTML = '<div class="cheat-server-item clean" style="justify-content:center"><span>✓ No known cheat servers found</span></div>';
      }
    }

    const profileAnalysis = document.querySelector('[data-profile-analysis]');
    if(profileAnalysis) profileAnalysis.textContent = cheatCheck.profileAnalysis || 'No profile analysis available.';
  }

  const evidence = document.querySelector('[data-evidence]');
  if(evidence){
    const categories = {
      'Process Analysis': [],
      'File System': [],
      'Memory Analysis': [],
      'Registry & Drivers': [],
      'Discord Intelligence': [],
      'Network': [],
      'FiveM Specific': [],
      'Deleted Artifacts': [],
      'Execution History': [],
      'Advanced Detection': []
    };

    scan.evidence.forEach(e => {
      const title = e.title.toLowerCase();
      if(title.includes('process') || title.includes('overlay') || title.includes('dll') || title.includes('injection')) categories['Process Analysis'].push(e);
      else if(title.includes('file') || title.includes('artifact') || title.includes('cache') || title.includes('loader') || title.includes('game folder')) categories['File System'].push(e);
      else if(title.includes('memory') || title.includes('strings') || title.includes('lua runtime') || title.includes('native')) categories['Memory Analysis'].push(e);
      else if(title.includes('registry') || title.includes('driver') || title.includes('persistence')) categories['Registry & Drivers'].push(e);
      else if(title.includes('discord') || title.includes('cheat server')) categories['Discord Intelligence'].push(e);
      else if(title.includes('network') || title.includes('connection')) categories['Network'].push(e);
      else if(title.includes('game launch') || title.includes('resource') || title.includes('fivem') || title.includes('manual')) categories['FiveM Specific'].push(e);
      else if(title.includes('deleted') || title.includes('recycle') || title.includes('usn') || title.includes('shadow')) categories['Deleted Artifacts'].push(e);
      else if(title.includes('execution') || title.includes('prefetch') || title.includes('amcache') || title.includes('bam') || title.includes('srum')) categories['Execution History'].push(e);
      else if(title.includes('alternate') || title.includes('ads') || title.includes('hidden') || title.includes('zero-width')) categories['Advanced Detection'].push(e);
      else categories['FiveM Specific'].push(e);
    });

    let html = '';
    for(const [cat, items] of Object.entries(categories)){
      if(items.length > 0){
        html += `<div style="margin-bottom:20px"><h4 style="font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:10px;border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:6px">${cat}</h4>`;
        html += items.map(e => `<article class="evidence">
          <div class="evidence-top"><strong>${e.title}</strong><span class="badge badge-${e.level}">${e.level.toUpperCase()}</span></div>
          <p>${e.detail}</p><span class="dim mono">${e.time}</span>
        </article>`).join('');
        html += '</div>';
      }
    }
    evidence.innerHTML = html;
  }

  function detectCheatTraces() {
    const evidence = scan.evidence || [];
    const detectedCheats = [];
    const suspiciousItems = [];

    evidence.forEach(item => {
      const detail = (item.detail || '').toLowerCase();
      const title = (item.title || '').toLowerCase();
      const combined = detail + ' ' + title;

      for (const [cheatName, cheatData] of Object.entries(window.THREEX_CHEAT_EVIDENCE || {})) {
        const cheatLower = cheatName.toLowerCase();

        if (combined.includes(cheatLower) || 
            cheatData.paths.some(p => combined.includes(p.toLowerCase())) ||
            cheatData.memory.some(m => combined.includes(m.toLowerCase()))) {

          if (!detectedCheats.find(c => c.name === cheatName)) {
            detectedCheats.push({
              name: cheatName,
              paths: cheatData.paths,
              memory: cheatData.memory,
              timestamps: cheatData.timestamps,
              hashes: cheatData.hashes,
              services: cheatData.services,
              risk: cheatData.risk
            });
          }
        }
      }

      const suspiciousPatterns = [
        'loader', 'injector', 'bypass', 'spoofer', 'cleaner',
        'unknown overlay', 'unsigned module', 'suspicious executable',
        'modified lua', 'cache manipulation', 'temp executable',
        'deleted', 'recycle', 'usn journal', 'shadow copy',
        'prefetch', 'amcache', 'bam', 'srum',
        'alternate data stream', 'ads', 'hidden file', 'zero-width'
      ];

      suspiciousPatterns.forEach(pattern => {
        if (combined.includes(pattern) && item.level !== 'clean') {
          suspiciousItems.push({
            pattern: pattern,
            title: item.title,
            detail: item.detail,
            level: item.level
          });
        }
      });
    });

    const cheatContainer = document.getElementById('cheat-traces');
    const cheatList = document.getElementById('cheat-traces-list');

    if (detectedCheats.length > 0 && cheatContainer && cheatList) {
      cheatContainer.style.display = 'block';
      cheatList.innerHTML = detectedCheats.map(cheat => `
        <div style="margin-bottom:16px;padding:16px;border:1px solid rgba(239,68,68,.2);border-radius:14px;background:rgba(239,68,68,.04);">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <strong style="font-size:16px;color:var(--danger);">${cheat.name}</strong>
            <span class="badge badge-threat" style="font-size:11px">RISK ${cheat.risk}</span>
          </div>
          ${cheat.paths.length > 0 ? `
            <div style="margin-bottom:8px;">
              <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Detected Paths</span>
              ${cheat.paths.map(p => `<div class="mono" style="font-size:12px;color:var(--text);margin-top:4px;padding:6px 10px;background:rgba(0,0,0,.3);border-radius:8px;">${p}</div>`).join('')}
            </div>
          ` : ''}
          ${cheat.memory.length > 0 ? `
            <div style="margin-bottom:8px;">
              <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Memory Addresses</span>
              ${cheat.memory.map(m => `<div class="mono" style="font-size:12px;color:var(--purple-2);margin-top:4px;padding:6px 10px;background:rgba(122,44,255,.08);border-radius:8px;">${m}</div>`).join('')}
            </div>
          ` : ''}
          ${cheat.timestamps.length > 0 ? `
            <div style="margin-bottom:8px;">
              <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Execution Timestamps</span>
              ${cheat.timestamps.map(t => `<div class="mono" style="font-size:12px;color:var(--warn);margin-top:4px;padding:6px 10px;background:rgba(245,158,11,.08);border-radius:8px;">${t}</div>`).join('')}
            </div>
          ` : ''}
          ${cheat.hashes.length > 0 ? `
            <div style="margin-bottom:8px;">
              <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Signatures</span>
              ${cheat.hashes.map(h => `<div class="mono" style="font-size:12px;color:var(--ok);margin-top:4px;padding:6px 10px;background:rgba(16,185,129,.08);border-radius:8px;">${h}</div>`).join('')}
            </div>
          ` : ''}
          <div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,.06);">
            <span style="font-size:11px;color:var(--muted);">Detected via: ${cheat.services.join(', ')}</span>
          </div>
        </div>
      `).join('');
    }

    const susContainer = document.getElementById('suspicious-traces');
    const susList = document.getElementById('suspicious-traces-list');

    if (suspiciousItems.length > 0 && susContainer && susList) {
      susContainer.style.display = 'block';
      susList.innerHTML = suspiciousItems.map(item => `
        <div style="margin-bottom:10px;padding:12px;border:1px solid rgba(245,158,11,.15);border-radius:12px;background:rgba(245,158,11,.03);">
          <strong style="font-size:14px;color:var(--warn);">${item.title}</strong>
          <p style="font-size:13px;color:var(--muted);margin:4px 0 0;">${item.detail}</p>
          <span style="font-size:11px;color:var(--dim);margin-top:4px;display:block;">Pattern match: ${item.pattern}</span>
        </div>
      `).join('');
    }
  }

  setTimeout(detectCheatTraces, 100);

  document.querySelector('[data-export]')?.addEventListener('click',()=>{
    window.toast?.('Report exported successfully.');
  });
})();