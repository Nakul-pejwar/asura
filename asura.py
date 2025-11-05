#!/usr/bin/env python3
"""
Asura - Advanced Bug Bounty Reconnaissance Tool
A comprehensive automated recon framework for bug bounty hunters
"""

import argparse
import subprocess
import os
import sys
from pathlib import Path
from datetime import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class Asura:
    def __init__(self, target, targets_file, output_dir, threads, passive_only, stealth):
        self.target = target
        self.targets_file = targets_file
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.passive_only = passive_only
        self.stealth = stealth
        self.domains = []
        
        # Create output directory structure
        self.setup_directories()
        
        # Banner
        self.print_banner()
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ___   _____ __  ______  ___ 
   /   | / ___// / / / __ \/   |
  / /| | \__ \/ / / / /_/ / /| |
 / ___ |___/ / /_/ / _, _/ ___ |
/_/  |_/____/\____/_/ |_/_/  |_|
                                
{Colors.END}{Colors.GREEN}Advanced Bug Bounty Reconnaissance Framework{Colors.END}
{Colors.YELLOW}By: Bug Bounty Hunters | For: Bug Bounty Hunters{Colors.END}
{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
"""
        print(banner)
    
    def setup_directories(self):
        """Create organized output directory structure"""
        dirs = [
            'subdomains', 'alive', 'screenshots', 'ports', 'vulnerabilities',
            'endpoints', 'parameters', 'js', 'nuclei', 'technologies',
            'cloud', 'historical', 'reports'
        ]
        
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        
        self.log(f"Created output directory: {self.output_dir}", Colors.GREEN)
    
    def log(self, message, color=Colors.CYAN):
        """Formatted logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}{Colors.END}")
    
    def run_command(self, cmd, output_file=None, silent=False):
        """Execute shell command safely"""
        try:
            if not silent:
                self.log(f"Running: {cmd[:100]}...", Colors.YELLOW)
            
            if output_file:
                with open(output_file, 'w') as f:
                    subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.PIPE, timeout=3600)
            else:
                subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
            
            return True
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {cmd[:50]}", Colors.RED)
            return False
        except Exception as e:
            self.log(f"Error: {str(e)}", Colors.RED)
            return False
    
    def load_targets(self):
        """Load target domains"""
        if self.target:
            self.domains = [self.target]
        elif self.targets_file:
            with open(self.targets_file, 'r') as f:
                self.domains = [line.strip() for line in f if line.strip()]
        
        self.log(f"Loaded {len(self.domains)} target(s)", Colors.GREEN)
        for domain in self.domains:
            self.log(f"  → {domain}", Colors.CYAN)
    
    def subdomain_enumeration(self):
        """Phase 1: Comprehensive subdomain enumeration"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 1: SUBDOMAIN ENUMERATION", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        targets = ' -d '.join(self.domains)
        all_subs = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        
        tools = []
        
        # Subfinder (passive)
        subfinder_out = self.output_dir / 'subdomains' / 'subfinder.txt'
        tools.append(f"subfinder -d {targets} -all -recursive -o {subfinder_out}")
        
        # Amass (passive)
        amass_out = self.output_dir / 'subdomains' / 'amass.txt'
        tools.append(f"amass enum -d {targets} -passive -o {amass_out}")
        
        # Assetfinder
        assetfinder_out = self.output_dir / 'subdomains' / 'assetfinder.txt'
        for domain in self.domains:
            tools.append(f"assetfinder --subs-only {domain} >> {assetfinder_out}")
        
        # Sublist3r
        sublist_out = self.output_dir / 'subdomains' / 'sublist3r.txt'
        for domain in self.domains:
            tools.append(f"python3 ~/tools/Sublist3r/sublist3r.py -d {domain} -o {sublist_out}")
        
        # Run all subdomain tools
        for cmd in tools:
            self.run_command(cmd)
        
        # Merge and deduplicate
        self.run_command(f"cat {self.output_dir}/subdomains/*.txt | sort -u | anew {all_subs}")
        
        with open(all_subs, 'r') as f:
            count = len(f.readlines())
        self.log(f"Found {count} unique subdomains", Colors.GREEN)
    
    def alive_check(self):
        """Phase 2: Check for alive hosts"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 2: ALIVE HOST DETECTION", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        all_subs = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        
        # HTTPX for alive check with multiple ports
        cmd = f"cat {all_subs} | httpx -silent -ports 80,443,8080,8000,8888,8443 -threads {self.threads} -o {alive_file}"
        self.run_command(cmd)
        
        with open(alive_file, 'r') as f:
            count = len(f.readlines())
        self.log(f"Found {count} alive hosts", Colors.GREEN)
    
    def port_scanning(self):
        """Phase 3: Port scanning"""
        if self.passive_only:
            self.log("Skipping port scan (passive mode)", Colors.YELLOW)
            return
        
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 3: PORT SCANNING", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        ports_file = self.output_dir / 'ports' / 'open_ports.txt'
        
        # Naabu for fast port scanning
        cmd = f"cat {alive_file} | naabu -silent -c {self.threads} -rate 1000 -o {ports_file}"
        if self.stealth:
            cmd += " -rate 100"  # Slower for stealth
        
        self.run_command(cmd)
    
    def screenshot_capture(self):
        """Phase 4: Visual reconnaissance"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 4: SCREENSHOT CAPTURE", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        screenshot_dir = self.output_dir / 'screenshots'
        
        cmd = f"cat {alive_file} | aquatone -out {screenshot_dir} -threads {self.threads}"
        self.run_command(cmd)
    
    def endpoint_discovery(self):
        """Phase 5: Crawling and endpoint discovery"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 5: ENDPOINT DISCOVERY", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        endpoints_file = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        
        # Katana for crawling
        cmd = f"cat {alive_file} | katana -silent -d 6 -jc -f qurl -c {self.threads} -o {endpoints_file}"
        self.run_command(cmd)
        
        # Waybackurls for historical data
        wayback_file = self.output_dir / 'historical' / 'wayback.txt'
        cmd = f"cat {alive_file} | waybackurls | tee {wayback_file} | anew {endpoints_file}"
        self.run_command(cmd)
        
        # GAU (GetAllUrls)
        gau_file = self.output_dir / 'historical' / 'gau.txt'
        cmd = f"cat {alive_file} | gau --threads {self.threads} | tee {gau_file} | anew {endpoints_file}"
        self.run_command(cmd)
        
        with open(endpoints_file, 'r') as f:
            count = len(f.readlines())
        self.log(f"Discovered {count} unique endpoints", Colors.GREEN)
    
    def javascript_analysis(self):
        """Phase 6: JavaScript reconnaissance"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 6: JAVASCRIPT ANALYSIS", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        js_file = self.output_dir / 'js' / 'js_files.txt'
        js_endpoints = self.output_dir / 'js' / 'js_endpoints.txt'
        
        # Extract JS files
        cmd = f"cat {alive_file} | subjs -c {self.threads} -o {js_file}"
        self.run_command(cmd)
        
        # Analyze JS for endpoints and secrets
        cmd = f"cat {js_file} | mantra | anew {js_endpoints}"
        self.run_command(cmd)
    
    def parameter_discovery(self):
        """Phase 7: Parameter mining"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 7: PARAMETER DISCOVERY", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        endpoints_file = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        params_file = self.output_dir / 'parameters' / 'parameters.txt'
        
        # Extract parameters from URLs
        cmd = f"cat {endpoints_file} | grep '=' | anew {params_file}"
        self.run_command(cmd)
        
        # Arjun for hidden parameter discovery
        for domain in self.domains:
            arjun_out = self.output_dir / 'parameters' / f'arjun_{domain}.txt'
            cmd = f"arjun -u https://{domain} -oT {arjun_out} -t {self.threads}"
            self.run_command(cmd)
    
    def technology_detection(self):
        """Phase 8: Technology stack fingerprinting"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 8: TECHNOLOGY DETECTION", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        tech_file = self.output_dir / 'technologies' / 'stack.json'
        
        # Wappalyzer equivalent using httpx
        cmd = f"cat {alive_file} | httpx -silent -tech-detect -json -o {tech_file}"
        self.run_command(cmd)
    
    def vulnerability_scanning(self):
        """Phase 9: Automated vulnerability detection"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 9: VULNERABILITY SCANNING", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        nuclei_file = self.output_dir / 'nuclei' / 'vulnerabilities.txt'
        
        # Nuclei scan
        cmd = f"cat {alive_file} | nuclei -silent -c {self.threads} -severity critical,high,medium -o {nuclei_file}"
        if self.stealth:
            cmd += " -rate-limit 10"
        
        self.run_command(cmd)
    
    def cloud_recon(self):
        """Phase 10: Cloud storage enumeration"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 10: CLOUD STORAGE RECON", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        cloud_file = self.output_dir / 'cloud' / 'buckets.txt'
        
        for domain in self.domains:
            cmd = f"cloudbrute -d {domain} -o {cloud_file}"
            self.run_command(cmd)
    
    def generate_report(self):
        """Generate final reconnaissance report"""
        self.log("="*60, Colors.HEADER)
        self.log("GENERATING FINAL REPORT", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        report_file = self.output_dir / 'reports' / f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        
        report = f"""
ASURA RECONNAISSANCE REPORT
{'='*60}
Target(s): {', '.join(self.domains)}
Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Output Directory: {self.output_dir}

STATISTICS:
{'='*60}
"""
        
        # Count results
        stats = {
            'Subdomains': self.output_dir / 'subdomains' / 'all_subdomains.txt',
            'Alive Hosts': self.output_dir / 'alive' / 'alive_hosts.txt',
            'Endpoints': self.output_dir / 'endpoints' / 'all_endpoints.txt',
            'JS Files': self.output_dir / 'js' / 'js_files.txt',
            'Parameters': self.output_dir / 'parameters' / 'parameters.txt',
            'Vulnerabilities': self.output_dir / 'nuclei' / 'vulnerabilities.txt',
        }
        
        for name, filepath in stats.items():
            if filepath.exists():
                with open(filepath, 'r') as f:
                    count = len(f.readlines())
                report += f"{name}: {count}\n"
        
        report += f"\n{'='*60}\n"
        report += f"All results saved in: {self.output_dir}\n"
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(report)
        self.log(f"Report saved: {report_file}", Colors.GREEN)
    
    def run(self):
        """Execute complete reconnaissance pipeline"""
        start_time = time.time()
        
        self.load_targets()
        
        # Execute all phases
        phases = [
            self.subdomain_enumeration,
            self.alive_check,
            self.port_scanning,
            self.screenshot_capture,
            self.endpoint_discovery,
            self.javascript_analysis,
            self.parameter_discovery,
            self.technology_detection,
            self.vulnerability_scanning,
            self.cloud_recon,
        ]
        
        for phase in phases:
            try:
                phase()
            except KeyboardInterrupt:
                self.log("\n\nScan interrupted by user", Colors.RED)
                sys.exit(1)
            except Exception as e:
                self.log(f"Error in {phase.__name__}: {str(e)}", Colors.RED)
                continue
        
        self.generate_report()
        
        elapsed = time.time() - start_time
        self.log(f"\n{'='*60}", Colors.GREEN)
        self.log(f"RECON COMPLETED IN {elapsed/60:.2f} MINUTES", Colors.GREEN)
        self.log(f"{'='*60}\n", Colors.GREEN)


def main():
    parser = argparse.ArgumentParser(
        description='Asura - Advanced Bug Bounty Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Single domain:
    python3 asura.py -d example.com -o output
  
  Multiple domains:
    python3 asura.py -l domains.txt -o output
  
  Passive only (no port scanning):
    python3 asura.py -d example.com -o output --passive
  
  Stealth mode:
    python3 asura.py -d example.com -o output --stealth
        '''
    )
    
    parser.add_argument('-d', '--domain', help='Single target domain')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--passive', action='store_true', help='Passive reconnaissance only')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode (slower but quieter)')
    
    args = parser.parse_args()
    
    if not args.domain and not args.list:
        parser.print_help() 
        sys.exit(1)
    
    # Initialize and run Asura
    asura = Asura(
        target=args.domain,
        targets_file=args.list,
        output_dir=args.output,
        threads=args.threads,
        passive_only=args.passive,
        stealth=args.stealth
    )
    
    asura.run()


if __name__ == '__main__':
    main()