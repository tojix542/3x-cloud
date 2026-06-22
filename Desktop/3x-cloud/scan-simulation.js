(function(){
  const ringProgress = document.querySelector('[data-ring-progress]');
  const ringInner = document.querySelector('[data-ring-inner]');
  const progressBar = document.querySelector('[data-sim-progress]');
  const percentText = document.querySelector('[data-sim-percent]');
  const statusTitle = document.querySelector('[data-sim-title]');
  const statusDesc = document.querySelector('[data-sim-desc]');
  const detailLines = document.querySelector('[data-sim-details]');
  const simContainer = document.querySelector('[data-simulation]');
  const resultContainer = document.querySelector('[data-result]');

  const steps = [
    { pct: 0, title: 'Initializing scanner...', desc: 'Preparing forensic environment', detail: 'Loading detection modules' },
    { pct: 5, title: 'Collecting artifacts...', desc: 'Scanning system directories', detail: 'Artifact collection started' },
    { pct: 10, title: 'Analyzing processes...', desc: 'Checking active runtime list', detail: 'Process enumeration active' },
    { pct: 15, title: 'Deep forensic scan...', desc: 'Multi-layer inspection running', detail: 'Memory regions mapped' },
    { pct: 20, title: 'Checking integrity...', desc: 'Verifying process signatures', detail: 'Signature database v2.4.1' },
    { pct: 25, title: 'Scanning strings...', desc: '10,000+ detection strings active', detail: 'Pattern matching in progress' },
    { pct: 30, title: 'Deleted files recovery...', desc: 'Scanning Recycle Bin & USN Journal', detail: 'Recovering deleted artifacts' },
    { pct: 35, title: 'Execution history check...', desc: 'Analyzing Prefetch & Amcache', detail: 'Program execution timeline' },
    { pct: 40, title: 'Registry deep scan...', desc: 'Checking persistence mechanisms', detail: 'HKCU/HKLM Run keys' },
    { pct: 45, title: 'Memory analysis...', desc: 'Scanning for injected code', detail: 'Byte patch detection active' },
    { pct: 50, title: 'Network artifacts...', desc: 'Checking DNS cache & connections', detail: 'Known cheat API endpoints' },
    { pct: 55, title: 'Discord intelligence...', desc: 'Cross-referencing cheat servers', detail: '214 servers checked' },
    { pct: 60, title: 'FiveM specific checks...', desc: 'Cache & resource validation', detail: 'Lua script integrity' },
    { pct: 65, title: 'Alternate data streams...', desc: 'Scanning for hidden payloads', detail: 'ADS detection active' },
    { pct: 70, title: 'Hidden file detection...', desc: 'Zero-width character scan', detail: 'Disguised extensions check' },
    { pct: 75, title: 'Reviewing evidence...', desc: 'Building evidence chain', detail: 'Chain of custody established' },
    { pct: 80, title: 'Finalizing report...', desc: 'Compiling scan results', detail: 'Classification algorithm running' },
    { pct: 85, title: 'Uploading results...', desc: 'Sending to cloud dashboard', detail: 'Secure TLS connection' },
    { pct: 90, title: 'Audit trail...', desc: 'Archiving forensic evidence', detail: 'SHA256 hashes generated' },
    { pct: 95, title: 'Completing...', desc: 'Final verification', detail: 'Report encrypted and sent' },
    { pct: 100, title: 'Scan complete', desc: 'Report generated successfully', detail: 'Redirecting to results...' }
  ];

  let currentStep = 0;
  let currentPct = 0;
  const totalDuration = 12000;
  const stepInterval = totalDuration / steps.length;

  function updateUI(pct, step) {
    const circumference = 440;
    const innerCircumference = 314;
    const offset = circumference - (pct / 100) * circumference;
    const innerOffset = innerCircumference - (pct / 100) * innerCircumference;

    if (ringProgress) ringProgress.style.strokeDashoffset = offset;
    if (ringInner) ringInner.style.strokeDashoffset = innerOffset;
    if (progressBar) progressBar.style.width = pct + '%';
    if (percentText) percentText.textContent = pct + '%';
    if (statusTitle) statusTitle.textContent = step.title;
    if (statusDesc) statusDesc.textContent = step.desc;

    if (detailLines) {
      detailLines.innerHTML = `
        <div class="sim-detail-line"><span>Status</span><span>${step.detail}</span></div>
        <div class="sim-detail-line"><span>Progress</span><span>${pct}%</span></div>
        <div class="sim-detail-line"><span>Elapsed</span><span>${Math.floor(pct / 100 * 12)}s</span></div>
        <div class="sim-detail-line"><span>Remaining</span><span>~${Math.ceil((100 - pct) / 100 * 12)}s</span></div>
      `;
    }
  }

  function animate() {
    if (currentStep >= steps.length) {
      setTimeout(() => {
        if (simContainer) simContainer.classList.add('hidden');
        if (resultContainer) {
          resultContainer.classList.add('show');
          setTimeout(() => {
            location.href = 'scan-report.html?id=3X-8721';
          }, 3000);
        }
      }, 500);
      return;
    }

    const step = steps[currentStep];
    const targetPct = step.pct;
    const stepDuration = stepInterval;
    const startTime = Date.now();
    const startPct = currentPct;

    function frame() {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / stepDuration, 1);
      currentPct = startPct + (targetPct - startPct) * progress;
      updateUI(Math.round(currentPct), step);

      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        currentStep++;
        setTimeout(animate, 100);
      }
    }

    frame();
  }

  setTimeout(animate, 800);
})();