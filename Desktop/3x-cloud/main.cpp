#include "scanner.h"
#include <iostream>
#include <string>

void PrintBanner() {
    std::cout << R"(
    ___   _____  __  ____________
   / _ | /  _/ |/ / / __/ __/ __/
  / __ |_/ /_>    < / _/_\ \\ \\ 
 /_/ |_/___//_/|_/ /___/___/___/ 

  Forensic Scanner v2.0 - Deep Trace Detection
  Target: )" << TARGET_ID << R"(
)" << std::endl;
}

void PrintUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -w <url>     Discord webhook URL" << std::endl;
    std::cout << "  -o <file>    Output file path" << std::endl;
    std::cout << "  -s           Silent mode (no console output)" << std::endl;
    std::cout << "  -h           Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string webhookUrl = WEBHOOK_URL;
    std::string outputFile = "";
    bool silent = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-w" && i + 1 < argc) {
            webhookUrl = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "-s") {
            silent = true;
        } else if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (!silent) {
        PrintBanner();
    }

    // Initialize COM for WMI
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        if (!silent) std::cerr << "Failed to initialize COM" << std::endl;
    }

    // Run scanner
    ForensicScanner scanner;
    auto results = scanner.RunFullScan();

    // Save report
    if (!outputFile.empty()) {
        if (scanner.SaveReport(outputFile)) {
            if (!silent) std::cout << "Report saved to: " << outputFile << std::endl;
        } else {
            if (!silent) std::cerr << "Failed to save report to: " << outputFile << std::endl;
        }
    }

    // Send to webhook
    if (!webhookUrl.empty() && webhookUrl != "https://discord.com/api/webhooks/REPLACE_ME") {
        if (!silent) std::cout << "Sending report to webhook..." << std::endl;
        if (scanner.SendReport(webhookUrl)) {
            if (!silent) std::cout << "Report sent successfully" << std::endl;
        } else {
            if (!silent) std::cerr << "Failed to send report" << std::endl;
        }
    }

    // Also save to default location
    std::string defaultPath = GetTempPathA() + "\\3x_scan_" + scanner.GetJsonReport().substr(0, 8) + ".json";
    scanner.SaveReport(defaultPath);

    CoUninitialize();
    return 0;
}
