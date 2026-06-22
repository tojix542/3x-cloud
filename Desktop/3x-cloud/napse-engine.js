// ============================================================
// 3X CLOUD NAPSE ENGINE v3.0
// Combined frontend detection engine for NAPSE-style PC checks
// Include this after cheat-evidence.js and behavior-detection.js
// ============================================================

window.THREEX_NAPSE_ENGINE = {
  version: '3.0-NAPSE',

  // Main analysis entry point — mimics NAPSE PC Checker
  analyzeScan: function(scanData) {
    const behaviorResult = window.THREEX_BEHAVIOR_DETECTION.analyze(scanData);
    const cheatTraces = this.detectCheatTraces(scanData);
    const suspiciousTraces = this.detectSuspiciousPatterns(scanData);
    const discordIntel = this.analyzeDiscordIntel(scanData);
    const systemAnomalies = this.analyzeSystemAnomalies(scanData);

    // Calculate NAPSE-style score
    let score = 100;
    if (behaviorResult.behaviorScore > 0) score -= behaviorResult.behaviorScore * 0.4;
    if (cheatTraces.length > 0) score -= cheatTraces.length * 15;
    if (suspiciousTraces.length > 0) score -= suspiciousTraces.length * 5;
    if (discordIntel.riskScore > 0) score -= discordIntel.riskScore * 0.3;
    if (systemAnomalies.length > 0) score -= systemAnomalies.length * 3;
    score = Math.max(0, Math.round(score));

    // Determine status
    let status = 'clean';
    if (score < 40 || cheatTraces.length > 2 || behaviorResult.threatLevel === 'CRITICAL') status = 'threat';
    else if (score < 70 || cheatTraces.length > 0 || suspiciousTraces.length > 3 || behaviorResult.threatLevel === 'HIGH') status = 'suspicious';

    return {
      score: score,
      status: status,
      behavior: behaviorResult,
      cheatTraces: cheatTraces,
      suspiciousTraces: suspiciousTraces,
      discordIntel: discordIntel,
      systemAnomalies: systemAnomalies,
      summary: this.generateSummary(status, score, behaviorResult, cheatTraces, suspiciousTraces)
    };
  },

  detectCheatTraces: function(scanData) {
    const evidence = scanData.evidence || [];
    const detected = [];

    evidence.forEach(item => {
      const combined = ((item.detail || '') + ' ' + (item.title || '')).toLowerCase();
      for (const [cheatName, cheatData] of Object.entries(window.THREEX_CHEAT_EVIDENCE || {})) {
        if (detected.find(c => c.name === cheatName)) continue;
        const cheatLower = cheatName.toLowerCase();
        if (combined.includes(cheatLower) || 
            cheatData.paths.some(p => combined.includes(p.toLowerCase())) ||
            cheatData.memory.some(m => combined.includes(m.toLowerCase()))) {
          detected.push({ name: cheatName, risk: cheatData.risk, sources: cheatData.services });
        }
      }
    });
    return detected;
  },

  detectSuspiciousPatterns: function(scanData) {
    const evidence = scanData.evidence || [];
    const patterns = [
      'loader', 'injector', 'bypass', 'spoofer', 'cleaner', 'unknown overlay',
      'unsigned module', 'suspicious executable', 'modified lua', 'cache manipulation',
      'temp executable', 'deleted', 'recycle', 'usn journal', 'shadow copy',
      'prefetch', 'amcache', 'bam', 'srum', 'alternate data stream', 'ads',
      'hidden file', 'zero-width', 'amsi', 'etw', 'wmi', 'reflective', 'hollow',
      'apc', 'thread hijack', 'manual map', 'process hollowing', 'dotnet inject'
    ];
    const found = [];
    evidence.forEach(item => {
      if (item.level === 'clean') return;
      const combined = ((item.detail || '') + ' ' + (item.title || '')).toLowerCase();
      patterns.forEach(p => {
        if (combined.includes(p)) found.push({ pattern: p, title: item.title, detail: item.detail, level: item.level });
      });
    });
    return found;
  },

  analyzeDiscordIntel: function(scanData) {
    const check = scanData.cheatServerCheck || {};
    return {
      checked: check.checked || 0,
      foundIn: check.foundIn || 0,
      riskScore: check.riskScore || 0,
      servers: check.servers || [],
      profileAnalysis: check.profileAnalysis || 'No Discord intelligence available.'
    };
  },

  analyzeSystemAnomalies: function(scanData) {
    const anomalies = [];
    const sys = scanData.system || {};
    if (sys.isAdmin === false) anomalies.push({ type: 'info', desc: 'Scan not run as Administrator — some checks may be incomplete' });
    if (sys.unknownDrivers && sys.unknownDrivers.length > 0) {
      sys.unknownDrivers.forEach(d => anomalies.push({ type: 'high', desc: `Unknown driver: ${d}` }));
    }
    if (sys.proxyEnabled) anomalies.push({ type: 'low', desc: 'Proxy enabled on system' });
    return anomalies;
  },

  generateSummary: function(status, score, behavior, cheats, suspicious) {
    if (status === 'clean') {
      return `No anomalies detected. Behavior score: ${behavior.behaviorScore}/100. ${cheats.length} cheat traces found. ${suspicious.length} suspicious patterns.`;
    } else if (status === 'suspicious') {
      return `Suspicious activity detected. Behavior score: ${behavior.behaviorScore}/100. ${cheats.length} cheat traces found. ${suspicious.length} suspicious patterns require manual review.`;
    } else {
      return `THREAT DETECTED. Behavior score: ${behavior.behaviorScore}/100. ${cheats.length} cheat traces found. ${suspicious.length} suspicious patterns. Immediate action recommended.`;
    }
  },

  // NAPSE-style evidence categorizer
  categorizeEvidence: function(evidence) {
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
      'Advanced Detection': [],
      'Behavior Analysis': []
    };

    evidence.forEach(e => {
      const title = (e.title || '').toLowerCase();
      if (title.includes('process') || title.includes('overlay') || title.includes('dll') || title.includes('injection')) categories['Process Analysis'].push(e);
      else if (title.includes('file') || title.includes('artifact') || title.includes('cache') || title.includes('loader') || title.includes('game folder')) categories['File System'].push(e);
      else if (title.includes('memory') || title.includes('strings') || title.includes('lua runtime') || title.includes('native')) categories['Memory Analysis'].push(e);
      else if (title.includes('registry') || title.includes('driver') || title.includes('persistence')) categories['Registry & Drivers'].push(e);
      else if (title.includes('discord') || title.includes('cheat server')) categories['Discord Intelligence'].push(e);
      else if (title.includes('network') || title.includes('connection')) categories['Network'].push(e);
      else if (title.includes('game launch') || title.includes('resource') || title.includes('fivem') || title.includes('manual')) categories['FiveM Specific'].push(e);
      else if (title.includes('deleted') || title.includes('recycle') || title.includes('usn') || title.includes('shadow')) categories['Deleted Artifacts'].push(e);
      else if (title.includes('execution') || title.includes('prefetch') || title.includes('amcache') || title.includes('bam') || title.includes('srum')) categories['Execution History'].push(e);
      else if (title.includes('alternate') || title.includes('ads') || title.includes('hidden') || title.includes('zero-width') || title.includes('amsi') || title.includes('etw') || title.includes('wmi')) categories['Advanced Detection'].push(e);
      else if (title.includes('behavior') || title.includes('napse') || title.includes('ocean') || title.includes('echo')) categories['Behavior Analysis'].push(e);
      else categories['FiveM Specific'].push(e);
    });
    return categories;
  }
};

// Auto-register for demo
console.log('[3X NAPSE Engine] v3.0 loaded. Behavior patterns:', Object.keys(window.THREEX_BEHAVIOR_DETECTION.patterns).length, '| Cheat signatures:', Object.keys(window.THREEX_CHEAT_EVIDENCE || {}).length);
