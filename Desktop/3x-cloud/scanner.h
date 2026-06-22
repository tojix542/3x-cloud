#pragma once
#include "common.h"

class ForensicScanner {
public:
    ForensicScanner();
    ~ForensicScanner();

    std::vector<ModuleResult> RunFullScan();
    std::string GetJsonReport();
    bool SendReport(const std::string& webhookUrl);
    bool SaveReport(const std::string& filePath);

    // Individual scan modules
    ModuleResult ScanSystemInfo();
    ModuleResult ScanBAM();
    ModuleResult ScanLSASS();
    ModuleResult ScanDNSCache();
    ModuleResult ScanPcaClient();
    ModuleResult ScanKeyAuth();
    ModuleResult ScanSuspiciousFiles();
    ModuleResult ScanServices();
    ModuleResult ScanRegistryArtifacts();
    ModuleResult ScanFileArtifacts();
    ModuleResult ScanMemoryPatterns();
    ModuleResult ScanDiscordTraces();
    ModuleResult ScanDeepTrace();
    ModuleResult ScanNetwork();
    ModuleResult ScanUSBDevices();
    ModuleResult ScanBrowserTraces();

private:
    std::vector<ModuleResult> results;
    std::string hwid;
    std::string timestamp;
    std::string scanId;
    std::string targetId;

    void AddFinding(ModuleResult& result, const std::string& type, 
                    const std::string& path, const std::string& key,
                    const std::string& value, const std::string& severity,
                    const std::string& description);
};
