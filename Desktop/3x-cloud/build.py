#!/usr/bin/env python3
"""
3X Scanner Builder
Auto-generates EXE with embedded target identifier
"""
import os
import sys
import shutil
import subprocess
import argparse
import re
from datetime import datetime

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def find_compiler():
    """Find available C++ compiler"""
    # Check for MSVC cl.exe
    cl_path = shutil.which("cl")
    if cl_path:
        return "msvc", cl_path

    # Check for MinGW g++
    gpp_path = shutil.which("g++")
    if gpp_path:
        return "mingw", gpp_path

    # Check for Clang
    clang_path = shutil.which("clang++")
    if clang_path:
        return "clang", clang_path

    return None, None

def build_msvc(target_id, output_name, webhook_url=None):
    """Build with MSVC"""
    ensure_dir(OUTPUT_DIR)

    # Read source files
    common_h = open(os.path.join(SRC_DIR, "common.h"), "r").read()
    common_cpp = open(os.path.join(SRC_DIR, "common.cpp"), "r").read()
    scanner_h = open(os.path.join(SRC_DIR, "scanner.h"), "r").read()
    scanner_cpp = open(os.path.join(SRC_DIR, "scanner.cpp"), "r").read()
    main_cpp = open(os.path.join(SRC_DIR, "main.cpp"), "r").read()

    # Replace TARGET_ID and WEBHOOK_URL
    common_h = common_h.replace('#define TARGET_ID "UNKNOWN"', f'#define TARGET_ID "{target_id}"')
    if webhook_url:
        common_h = common_h.replace('#define WEBHOOK_URL "https://discord.com/api/webhooks/REPLACE_ME"', 
                                     f'#define WEBHOOK_URL "{webhook_url}"')

    # Write temp source
    temp_dir = os.path.join(OUTPUT_DIR, "build_temp")
    ensure_dir(temp_dir)

    with open(os.path.join(temp_dir, "common.h"), "w") as f:
        f.write(common_h)
    with open(os.path.join(temp_dir, "common.cpp"), "w") as f:
        f.write(common_cpp)
    with open(os.path.join(temp_dir, "scanner.h"), "w") as f:
        f.write(scanner_h)
    with open(os.path.join(temp_dir, "scanner.cpp"), "w") as f:
        f.write(scanner_cpp)
    with open(os.path.join(temp_dir, "main.cpp"), "w") as f:
        f.write(main_cpp)

    # Compile
    output_exe = os.path.join(OUTPUT_DIR, f"{output_name}.exe")
    cmd = [
        "cl.exe",
        "/EHsc", "/O2", "/MT", "/W3",
        "/Fe" + output_exe,
        "/Fo" + os.path.join(temp_dir, ""),
        os.path.join(temp_dir, "main.cpp"),
        os.path.join(temp_dir, "scanner.cpp"),
        os.path.join(temp_dir, "common.cpp"),
        "winhttp.lib", "iphlpapi.lib", "ws2_32.lib", "shlwapi.lib",
        "wintrust.lib", "crypt32.lib", "psapi.lib", "dnsapi.lib",
        "setupapi.lib", "wbemuuid.lib"
    ]

    print(f"Building with MSVC: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"Build successful: {output_exe}")
        return output_exe
    else:
        print(f"Build failed: {result.stderr}")
        return None

def build_mingw(target_id, output_name, webhook_url=None):
    """Build with MinGW"""
    ensure_dir(OUTPUT_DIR)

    # Read and modify source
    common_h = open(os.path.join(SRC_DIR, "common.h"), "r").read()
    common_cpp = open(os.path.join(SRC_DIR, "common.cpp"), "r").read()
    scanner_h = open(os.path.join(SRC_DIR, "scanner.h"), "r").read()
    scanner_cpp = open(os.path.join(SRC_DIR, "scanner.cpp"), "r").read()
    main_cpp = open(os.path.join(SRC_DIR, "main.cpp"), "r").read()

    common_h = common_h.replace('#define TARGET_ID "UNKNOWN"', f'#define TARGET_ID "{target_id}"')
    if webhook_url:
        common_h = common_h.replace('#define WEBHOOK_URL "https://discord.com/api/webhooks/REPLACE_ME"', 
                                     f'#define WEBHOOK_URL "{webhook_url}"')

    temp_dir = os.path.join(OUTPUT_DIR, "build_temp")
    ensure_dir(temp_dir)

    with open(os.path.join(temp_dir, "common.h"), "w") as f:
        f.write(common_h)
    with open(os.path.join(temp_dir, "common.cpp"), "w") as f:
        f.write(common_cpp)
    with open(os.path.join(temp_dir, "scanner.h"), "w") as f:
        f.write(scanner_h)
    with open(os.path.join(temp_dir, "scanner.cpp"), "w") as f:
        f.write(scanner_cpp)
    with open(os.path.join(temp_dir, "main.cpp"), "w") as f:
        f.write(main_cpp)

    output_exe = os.path.join(OUTPUT_DIR, f"{output_name}.exe")
    cmd = [
        "g++", "-O2", "-static", "-static-libgcc", "-static-libstdc++",
        "-o", output_exe,
        os.path.join(temp_dir, "main.cpp"),
        os.path.join(temp_dir, "scanner.cpp"),
        os.path.join(temp_dir, "common.cpp"),
        "-lwinhttp", "-liphlpapi", "-lws2_32", "-lshlwapi",
        "-lwintrust", "-lcrypt32", "-lpsapi", "-ldnsapi",
        "-lsetupapi", "-lwbemuuid", "-lole32", "-loleaut32",
        "-luuid", "-lcomdlg32", "-lshell32"
    ]

    print(f"Building with MinGW: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"Build successful: {output_exe}")
        return output_exe
    else:
        print(f"Build failed: {result.stderr}")
        return None

def main():
    parser = argparse.ArgumentParser(description="3X Scanner Builder")
    parser.add_argument("target_id", help="Target identifier to embed")
    parser.add_argument("-o", "--output", default="3x_scanner", help="Output filename")
    parser.add_argument("-w", "--webhook", help="Discord webhook URL")
    parser.add_argument("-c", "--compiler", choices=["msvc", "mingw", "clang"], help="Force compiler")
    args = parser.parse_args()

    compiler_type, compiler_path = find_compiler()

    if args.compiler:
        compiler_type = args.compiler
        if compiler_type == "msvc":
            compiler_path = shutil.which("cl")
        elif compiler_type == "mingw":
            compiler_path = shutil.which("g++")
        elif compiler_type == "clang":
            compiler_path = shutil.which("clang++")

    if not compiler_path:
        print("ERROR: No C++ compiler found!")
        print("Install Visual Studio (MSVC) or MinGW-w64")
        print("MinGW download: https://www.mingw-w64.org/downloads/")
        print("MSVC download: https://visualstudio.microsoft.com/downloads/")
        sys.exit(1)

    print(f"Using compiler: {compiler_type} ({compiler_path})")
    print(f"Target ID: {args.target_id}")
    print(f"Output: {args.output}.exe")

    if compiler_type == "msvc":
        result = build_msvc(args.target_id, args.output, args.webhook)
    else:
        result = build_mingw(args.target_id, args.output, args.webhook)

    if result:
        print(f"\nBuild complete!")
        print(f"EXE: {result}")
        print(f"Target ID embedded: {args.target_id}")
        print(f"Timestamp: {datetime.now().isoformat()}")
    else:
        print("\nBuild failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
