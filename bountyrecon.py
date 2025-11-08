#!/usr/bin/env python3

"""
BountyRecon - Unified Bug Bounty Reconnaissance & Vulnerability Scanner
Created by: 0xZan
Description: Automated security assessment tool combining 7 powerful tools
"""

import os
import sys
import subprocess
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
import re

# Color codes for terminal output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Banner
def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
   ___                   _         ____                       
  / __\ ___  _   _ _ __ | |_ _   _|  _ \ ___  ___ ___  _ __  
 /__\/// _ \| | | | '_ \| __| | | | |_) / _ \/ __/ _ \| '_ \ 
/ \/  \ (_) | |_| | | | | |_| |_| |  _ <  __/ (_| (_) | | | |
\_____/\___/ \__,_|_| |_|\__|\__, |_| \_\___|\___\___/|_| |_|
                             |___/                            
{Colors.END}
{Colors.YELLOW}        Bug Bounty Reconnaissance & Vulnerability Scanner{Colors.END}
{Colors.GREEN}                   Created by: 0xZan{Colors.END}
{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.END}
    """
    print(banner)

# Configuration
class Config:
    def __init__(self):
        self.home_dir = Path.home()
        self.base_dir = self.home_dir / "0xZan"
        
        # Tool directories
        self.nmap_dir = self.base_dir / "tools" / "nmap"
        self.metasploit_dir = self.base_dir / "tools" / "metasploit"
        self.sqlmap_dir = self.base_dir / "tools" / "sqlmap"
        self.nuclei_dir = self.base_dir / "tools" / "nuclei"
        self.subfinder_dir = self.base_dir / "tools" / "subfinder"
        self.httpx_dir = self.base_dir / "tools" / "httpx"
        self.ffuf_dir = self.base_dir / "tools" / "ffuf"
        
        # Output directories - Using Results instead of reports
        self.results_dir = self.base_dir / "Results"
        self.wordlists_dir = self.base_dir / "wordlists"
        
        # Go binary path
        self.go_bin = self.home_dir / "go" / "bin"
        
    def ensure_dirs(self):
        """Ensure all required directories exist"""
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.base_dir.mkdir(parents=True, exist_ok=True)

# Utility functions
def log_info(message):
    print(f"{Colors.BLUE}[*]{Colors.END} {message}")

def log_success(message):
    print(f"{Colors.GREEN}[✓]{Colors.END} {message}")

def log_warning(message):
    print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

def log_error(message):
    print(f"{Colors.RED}[✗]{Colors.END} {message}")

def log_section(message):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{message}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}\n")

def run_command(command, description, timeout=300):
    """Run a shell command and return output"""
    log_info(f"{description}...")
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log_error(f"Command timed out after {timeout} seconds")
        return "", f"Timeout after {timeout}s", 1
    except Exception as e:
        log_error(f"Command failed: {str(e)}")
        return "", str(e), 1

def update_list_script(results_dir):
    """Create/update the list script that shows all scans with numbered access"""
    list_script = results_dir / "list"
    
    # Get all scan directories
    scan_dirs = sorted([d for d in results_dir.iterdir() if d.is_dir()], 
                      key=lambda x: x.stat().st_mtime, reverse=True)
    
    # Remove old symlinks
    for item in results_dir.iterdir():
        if item.is_symlink() and item.name.isdigit():
            item.unlink()
    
    # Create list script content
    script_content = "#!/bin/bash\n\n"
    script_content += f"# BountyRecon Scan Results\n"
    script_content += f"# Total scans: {len(scan_dirs)}\n\n"
    script_content += f"echo -e '\\033[1;36m═══════════════════════════════════════════════════════════\\033[0m'\n"
    script_content += f"echo -e '\\033[1;36m            BountyRecon - Scan Results\\033[0m'\n"
    script_content += f"echo -e '\\033[1;36m═══════════════════════════════════════════════════════════\\033[0m\\n'\n\n"
    
    # Create numbered symlinks and add to list
    for idx, scan_dir in enumerate(scan_dirs, 1):
        # Create symlink
        symlink = results_dir / str(idx)
        symlink.symlink_to(scan_dir.name)
        
        # Extract info from directory name
        # Format: targetname_YYYYMMDD_HHMMSS or scan_targetname_YYYYMMDD_HHMMSS
        dir_name = scan_dir.name
        parts = dir_name.rsplit('_', 2)
        
        if len(parts) >= 3:
            target_name = parts[0].replace('scan_', '')
            date_str = parts[1]
            time_str = parts[2]
            
            # Format date and time nicely
            try:
                dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_date = f"{date_str} {time_str}"
        else:
            target_name = dir_name
            formatted_date = "Unknown date"
        
        # Add to script
        script_content += f"echo -e '\\033[1;33m[{idx}]\\033[0m \\033[1;37m{target_name}\\033[0m'\n"
        script_content += f"echo -e '    📅 {formatted_date}'\n"
        script_content += f"echo -e '    📂 cd {idx}'\n"
        script_content += f"echo -e '    📄 cat {idx}/scan.txt'\n"
        script_content += f"echo ''\n\n"
    
    script_content += f"echo -e '\\033[1;32mTo access a scan: cd <number>\\033[0m'\n"
    script_content += f"echo -e '\\033[1;32mTo view report: cat <number>/scan.txt\\033[0m\\n'\n"
    
    # Write script
    with open(list_script, 'w') as f:
        f.write(script_content)
    
    # Make executable
    list_script.chmod(0o755)

# Scanner class
class BountyReconScanner:
    def __init__(self, target, target_type, quick=False):
        self.config = Config()
        self.config.ensure_dirs()
        
        self.target = target
        self.target_type = target_type
        self.quick = quick
        
        # Clean target name for directory
        self.target_clean = re.sub(r'[^\w\-.]', '_', target)
        
        # Create scan directory with cleaner naming (no "scan_" prefix)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_dir = self.config.results_dir / f"{self.target_clean}_{timestamp}"
        self.scan_dir.mkdir(exist_ok=True)
        
        # Results storage
        self.results = {
            'target': self.target_clean,
            'type': self.target_type,
            'scan_time': timestamp,
            'subdomains': [],
            'live_hosts': [],
            'open_ports': [],
            'vulnerabilities': [],
            'findings': []
        }
        
        log_info(f"Scan directory: {self.scan_dir}")
    
    def run_subfinder(self):
        """Run Subfinder for subdomain enumeration"""
        if self.target_type != 'domain':
            log_warning("Skipping Subfinder (target is not a domain)")
            return
        
        log_section("PHASE 1: Subdomain Enumeration (Subfinder)")
        
        output_file = self.scan_dir / "subdomains.txt"
        subfinder_bin = self.config.go_bin / "subfinder"
        
        command = f"{subfinder_bin} -d {self.target_clean} -o {output_file} -silent"
        stdout, stderr, code = run_command(command, "Running Subfinder", timeout=180)
        
        if output_file.exists():
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                self.results['subdomains'] = subdomains
                log_success(f"Found {len(subdomains)} subdomains")
                
                # Show first 5 subdomains
                if subdomains:
                    print(f"\n{Colors.CYAN}Sample subdomains:{Colors.END}")
                    for subdomain in subdomains[:5]:
                        print(f"  • {subdomain}")
                    if len(subdomains) > 5:
                        print(f"  ... and {len(subdomains) - 5} more")
        else:
            log_warning("No subdomains found")
    
    def run_httpx(self):
        """Run httpx to probe for live HTTP services"""
        log_section("PHASE 2: HTTP Service Probing (httpx)")
        
        # Determine input source
        subdomains_file = self.scan_dir / "subdomains.txt"
        
        if subdomains_file.exists() and subdomains_file.stat().st_size > 0:
            input_source = f"-l {subdomains_file}"
        else:
            input_source = f"-u {self.target}"
        
        output_file = self.scan_dir / "live_hosts.txt"
        httpx_bin = self.config.go_bin / "httpx"
        
        command = f"{httpx_bin} {input_source} -o {output_file} -silent -tech-detect -status-code"
        stdout, stderr, code = run_command(command, "Running httpx", timeout=300)
        
        if output_file.exists():
            with open(output_file, 'r') as f:
                live_hosts = [line.strip() for line in f if line.strip()]
                self.results['live_hosts'] = live_hosts
                log_success(f"Found {len(live_hosts)} live hosts")
                
                # Show live hosts
                if live_hosts:
                    print(f"\n{Colors.CYAN}Live hosts:{Colors.END}")
                    for host in live_hosts[:10]:
                        print(f"  • {host}")
                    if len(live_hosts) > 10:
                        print(f"  ... and {len(live_hosts) - 10} more")
        else:
            log_warning("No live hosts found")
    
    def run_nmap(self):
        """Run Nmap for port scanning"""
        log_section("PHASE 3: Port Scanning (Nmap)")
        
        # Get targets
        live_hosts_file = self.scan_dir / "live_hosts.txt"
        
        if live_hosts_file.exists() and live_hosts_file.stat().st_size > 0:
            # Extract IPs/hosts from httpx output
            with open(live_hosts_file, 'r') as f:
                hosts = []
                for line in f:
                    # Extract domain from httpx output (format: http://domain [status])
                    match = re.search(r'https?://([^\s\[]+)', line)
                    if match:
                        hosts.append(match.group(1))
                
                if hosts:
                    target = hosts[0]  # Scan first host for demo
                else:
                    target = self.target
        else:
            target = self.target
        
        output_file = self.scan_dir / "nmap_scan.txt"
        
        # Quick scan of top ports
        if self.quick:
            command = f"nmap -T4 --top-ports 100 -oN {output_file} {target}"
        else:
            command = f"nmap -T4 -p- -oN {output_file} {target}"
        
        stdout, stderr, code = run_command(command, f"Running Nmap on {target}", timeout=600)
        
        # Parse nmap results
        if output_file.exists():
            with open(output_file, 'r') as f:
                content = f.read()
                # Extract open ports
                open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', content)
                self.results['open_ports'] = [
                    {'port': port, 'service': service} 
                    for port, service in open_ports
                ]
                log_success(f"Found {len(open_ports)} open ports")
                
                if open_ports:
                    print(f"\n{Colors.CYAN}Open ports:{Colors.END}")
                    for port, service in open_ports[:10]:
                        print(f"  • Port {port}: {service}")
        else:
            log_warning("Nmap scan produced no results")
    
    def run_nuclei(self):
        """Run Nuclei for vulnerability scanning"""
        log_section("PHASE 4: Vulnerability Scanning (Nuclei)")
        
        # Get targets
        live_hosts_file = self.scan_dir / "live_hosts.txt"
        
        if live_hosts_file.exists() and live_hosts_file.stat().st_size > 0:
            input_source = f"-l {live_hosts_file}"
        else:
            input_source = f"-u {self.target}"
        
        output_file = self.scan_dir / "nuclei_results.txt"
        nuclei_bin = self.config.go_bin / "nuclei"
        
        # Severity filter based on mode
        if self.quick:
            severity = "critical,high"
        else:
            severity = "critical,high,medium"
        
        command = f"{nuclei_bin} {input_source} -severity {severity} -o {output_file} -silent"
        stdout, stderr, code = run_command(command, "Running Nuclei", timeout=600)
        
        vulnerabilities = []
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        vulnerabilities.append(line.strip())
                
                self.results['vulnerabilities'] = vulnerabilities
                
                if vulnerabilities:
                    log_warning(f"Found {len(vulnerabilities)} potential vulnerabilities!")
                    print(f"\n{Colors.RED}Vulnerabilities:{Colors.END}")
                    for vuln in vulnerabilities[:5]:
                        print(f"  • {vuln}")
                    if len(vulnerabilities) > 5:
                        print(f"  ... and {len(vulnerabilities) - 5} more")
                else:
                    log_success("No critical vulnerabilities detected")
        else:
            log_success("No vulnerabilities found")
        
        return vulnerabilities
    
    def run_ffuf(self):
        """Run ffuf for directory discovery"""
        if self.quick:
            return
        
        log_section("PHASE 5: Directory Discovery (ffuf)")
        
        # Get target URL
        live_hosts_file = self.scan_dir / "live_hosts.txt"
        
        if live_hosts_file.exists() and live_hosts_file.stat().st_size > 0:
            with open(live_hosts_file, 'r') as f:
                first_host = f.readline().strip()
                # Extract URL
                match = re.search(r'(https?://[^\s\[]+)', first_host)
                if match:
                    target_url = match.group(1)
                else:
                    target_url = f"http://{self.target}"
        else:
            target_url = f"http://{self.target}"
        
        # Check for wordlist
        wordlist = self.config.wordlists_dir / "SecLists" / "Discovery" / "Web-Content" / "common.txt"
        
        if not wordlist.exists():
            log_warning("Wordlist not found, skipping directory discovery")
            return
        
        output_file = self.scan_dir / "ffuf_results.json"
        ffuf_bin = self.config.go_bin / "ffuf"
        
        command = f"{ffuf_bin} -u {target_url}/FUZZ -w {wordlist} -mc 200,301,302,403 -o {output_file} -of json -s"
        stdout, stderr, code = run_command(command, f"Running ffuf on {target_url}", timeout=300)
        
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    results = data.get('results', [])
                    log_success(f"Found {len(results)} directories/files")
                    
                    if results:
                        print(f"\n{Colors.CYAN}Discovered paths:{Colors.END}")
                        for result in results[:10]:
                            print(f"  • {result.get('url', 'Unknown')}")
            except:
                log_warning("Could not parse ffuf results")
        else:
            log_warning("Directory discovery produced no results")
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        log_section("Generating Report")
        
        report_file = self.scan_dir / "scan.txt"
        
        # Build report
        report = f"""
{'='*70}
BOUNTYRECON SCAN REPORT
{'='*70}

Target: {self.target}
Type: {self.target_type}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Mode: {'Quick Scan' if self.quick else 'Full Scan'}

{'='*70}
SUMMARY
{'='*70}

• Subdomains Found: {len(self.results['subdomains'])}
• Live Hosts: {len(self.results['live_hosts'])}
• Open Ports: {len(self.results['open_ports'])}
• Vulnerabilities: {len(self.results['vulnerabilities'])}

{'='*70}
SUBDOMAINS
{'='*70}

"""
        if self.results['subdomains']:
            for subdomain in self.results['subdomains']:
                report += f"• {subdomain}\n"
        else:
            report += "No subdomains found.\n"
        
        report += f"""
{'='*70}
LIVE HOSTS
{'='*70}

"""
        if self.results['live_hosts']:
            for host in self.results['live_hosts']:
                report += f"• {host}\n"
        else:
            report += "No live hosts found.\n"
        
        report += f"""
{'='*70}
OPEN PORTS
{'='*70}

"""
        if self.results['open_ports']:
            for port_info in self.results['open_ports']:
                report += f"• Port {port_info['port']}: {port_info['service']}\n"
        else:
            report += "No open ports found.\n"
        
        report += f"""
{'='*70}
VULNERABILITIES
{'='*70}

"""
        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                report += f"• {vuln}\n"
        else:
            report += "No vulnerabilities detected.\n"
        
        report += f"""
{'='*70}
RECOMMENDATIONS
{'='*70}

"""
        if self.results['vulnerabilities']:
            report += f"""
1. Review all identified vulnerabilities immediately
2. Prioritize critical and high severity findings
3. Use specialized tools (sqlmap, Metasploit) for deeper testing
4. Document findings for bug bounty submission
5. Verify vulnerabilities manually before reporting

For detailed exploitation guidance, check individual tool outputs in:
{self.scan_dir}
"""
        else:
            report += """
No critical vulnerabilities found in automated scan.

Recommended next steps:
1. Perform manual testing on discovered endpoints
2. Test for business logic flaws
3. Check authentication and authorization
4. Review API endpoints for security issues
5. Test for IDOR and privilege escalation

"""
        
        report += f"\n{'='*70}\n"
        report += "Scan completed successfully!\n"
        report += f"All results saved to: {self.scan_dir}\n"
        report += f"{'='*70}\n"
        
        # Write report
        with open(report_file, 'w') as f:
            f.write(report)
        
        log_success(f"Report generated: {report_file}")
        
        # Save JSON results
        json_file = self.scan_dir / "results.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        log_success(f"JSON results saved: {json_file}")
        
        return report_file
    
    def run_full_scan(self):
        """Execute complete reconnaissance and vulnerability scan"""
        start_time = time.time()
        
        print(f"\n{Colors.BOLD}Target: {Colors.CYAN}{self.target}{Colors.END}")
        print(f"{Colors.BOLD}Type: {Colors.CYAN}{self.target_type}{Colors.END}")
        print(f"{Colors.BOLD}Mode: {Colors.CYAN}{'Quick Scan' if self.quick else 'Full Scan'}{Colors.END}\n")
        
        try:
            # Phase 1: Subdomain Enumeration
            self.run_subfinder()
            
            # Phase 2: HTTP Probing
            self.run_httpx()
            
            # Phase 3: Port Scanning
            self.run_nmap()
            
            # Phase 4: Vulnerability Scanning
            vulnerabilities = self.run_nuclei()
            
            # Phase 5: Directory Discovery (full mode only)
            if not self.quick:
                self.run_ffuf()
            
            # Generate final report
            report_file = self.generate_report()
            
            # Update list script with numbered access
            update_list_script(self.config.results_dir)
            
            # Calculate duration
            duration = time.time() - start_time
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            
            # Final summary
            print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}{Colors.BOLD}SCAN COMPLETED SUCCESSFULLY!{Colors.END}")
            print(f"{Colors.GREEN}{Colors.BOLD}{'='*60}{Colors.END}\n")
            
            print(f"{Colors.CYAN}Duration:{Colors.END} {minutes}m {seconds}s")
            print(f"{Colors.CYAN}Report:{Colors.END} {report_file}")
            print(f"{Colors.CYAN}Results:{Colors.END} {self.scan_dir}\n")
            
            if vulnerabilities:
                print(f"{Colors.RED}⚠️  {len(vulnerabilities)} potential vulnerabilities detected!{Colors.END}")
                print(f"{Colors.YELLOW}Review the report for details and recommendations.{Colors.END}\n")
            else:
                print(f"{Colors.GREEN}✓ No critical vulnerabilities detected in automated scan{Colors.END}\n")
            
            print(f"{Colors.CYAN}To view all scans:{Colors.END} cd ~/0xZan/Results && ./list\n")
            
        except KeyboardInterrupt:
            log_warning("\nScan interrupted by user")
            print(f"\n{Colors.YELLOW}Partial results saved to: {self.scan_dir}{Colors.END}\n")
            sys.exit(0)
        except Exception as e:
            log_error(f"Scan failed: {str(e)}")
            sys.exit(1)

# Main function
def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="BountyRecon - Unified Bug Bounty Reconnaissance Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bountyrecon.py -d example.com
  python3 bountyrecon.py -u https://example.com --quick
  python3 bountyrecon.py -i 192.168.1.1

Created by: 0xZan
        """
    )
    
    # Target options (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-d', '--domain', help='Target domain (e.g., example.com)')
    target_group.add_argument('-u', '--url', help='Target URL (e.g., https://example.com)')
    target_group.add_argument('-i', '--ip', help='Target IP address')
    
    # Scan options
    parser.add_argument('--quick', action='store_true', 
                       help='Quick scan mode (faster, skips directory discovery)')
    parser.add_argument('-o', '--output', help='Custom output directory (optional)')
    
    args = parser.parse_args()
    
    # Determine target and type
    if args.domain:
        target = args.domain
        target_type = 'domain'
    elif args.url:
        target = args.url
        target_type = 'url'
    else:
        target = args.ip
        target_type = 'ip'
    
    # Create scanner and run
    scanner = BountyReconScanner(target, target_type, quick=args.quick)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()