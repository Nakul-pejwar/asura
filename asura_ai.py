#!/usr/bin/env python3
"""
Asura AI - Autonomous AI Reconnaissance Framework
AI-powered bug bounty recon with intelligent agents for analysis, prioritization, and PoC generation
"""

import argparse
import subprocess
import os
import sys
import json
from pathlib import Path
from datetime import datetime
import time
from typing import List, Dict, Any
import asyncio

# AI/LLM imports
try:
    from langchain_openai import ChatOpenAI
    from langchain_anthropic import ChatAnthropic
    from langchain_community.chat_models import Ollama
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.messages import HumanMessage, SystemMessage

    import docker
    HAS_AI = True
except ImportError:
    HAS_AI = False
    print("⚠️  AI libraries not installed. Run: pip install -r requirements.txt")

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    PURPLE = '\033[35m'

class AIAgents:
    """AI Agent Swarm for intelligent recon analysis"""
    
    def __init__(self, model_name="gpt-4o", api_key=None):
        self.model_name = model_name
        self.llm = None
        self.docker_client = None
        
        if not HAS_AI:
            return
            
        # Initialize LLM based on provider
        if "gpt" in model_name or "openai" in model_name:
            self.llm = ChatOpenAI(
                model=model_name.replace("openai/", ""),
                api_key=api_key or os.getenv("OPENAI_API_KEY"),
                temperature=0.7
            )
        elif "claude" in model_name or "anthropic" in model_name:
            self.llm = ChatAnthropic(
                model=model_name.replace("anthropic/", ""),
                api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
                temperature=0.7
            )
        elif "ollama" in model_name:
            self.llm = Ollama(model=model_name.replace("ollama/", ""))
        
        # Initialize Docker for sandboxed PoCs
        try:
            if os.getenv("DOCKER_ENABLED", "false").lower() == "true":
                self.docker_client = docker.from_env()
        except:
            pass
    
    def analyze_subdomains(self, subdomains: List[str], instruction: str = "") -> Dict:
        """Recon Coordinator: Prioritize subdomains by attack surface"""
        if not self.llm:
            return {"error": "AI not initialized"}
        
        prompt = f"""You are a bug bounty hunter analyzing subdomain reconnaissance data.
        
Subdomains found: {len(subdomains)}
Sample: {subdomains[:20]}

{f'Custom instruction: {instruction}' if instruction else ''}

Analyze these subdomains and:
1. Identify high-value targets (admin panels, API gateways, dev/staging)
2. Group by potential attack surface (auth, payment, file upload, etc.)
3. Flag suspicious patterns (old tech, leaked credentials hints)
4. Suggest priority order for testing

Return as JSON: {{"high_priority": [], "medium_priority": [], "patterns_found": [], "recommendations": []}}"""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            return json.loads(response.content.strip('```json').strip('```'))
        except Exception as e:
            return {"error": str(e), "raw_response": response.content if 'response' in locals() else ""}
    
    def analyze_endpoints(self, endpoints: List[str], js_secrets: List[str] = None) -> Dict:
        """Surface Mapper: Find hidden gems in endpoints and JS"""
        if not self.llm:
            return {"error": "AI not initialized"}
        
        prompt = f"""You are analyzing web endpoints for bug bounty hunting.

Endpoints found: {len(endpoints)}
Sample endpoints: {endpoints[:30]}
{f'JS Secrets found: {js_secrets[:10]}' if js_secrets else ''}

Identify:
1. IDOR-prone endpoints (/user/123, /api/document/456)
2. Injection points (search params, filters)
3. Sensitive paths (/admin, /api/internal, /.git)
4. Exposed secrets from JS (API keys, tokens)
5. Logic flaw candidates (checkout, payment, reset password flows)

Return JSON: {{"idor_candidates": [], "injection_points": [], "sensitive_paths": [], "secrets": [], "logic_flaws": []}}"""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            return json.loads(response.content.strip('```json').strip('```'))
        except:
            return {"error": "Failed to parse AI response"}
    
    def generate_fuzzing_payloads(self, parameters: List[str], vuln_type: str = "all") -> Dict:
        """Fuzz Hunter: Generate smart payloads for discovered parameters"""
        if not self.llm:
            return {"error": "AI not initialized"}
        
        prompt = f"""Generate targeted fuzzing payloads for bug bounty testing.

Parameters: {parameters[:20]}
Focus: {vuln_type}

Create payloads for:
1. SQL Injection (if vuln_type includes 'sqli' or 'all')
2. XSS (if vuln_type includes 'xss' or 'all')
3. IDOR (if vuln_type includes 'idor' or 'all')
4. Open Redirect
5. SSRF

For each parameter, suggest:
- Payload variations
- Detection method
- Expected vulnerable behavior

Return JSON: {{"payloads": [{{"param": "id", "type": "sqli", "payload": "1' OR '1'='1", "detection": "time delay"}}]}}"""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            return json.loads(response.content.strip('```json').strip('```'))
        except:
            return {"error": "Failed to generate payloads"}
    
    def validate_vulnerability(self, vuln_data: Dict, poc_enabled: bool = False) -> Dict:
        """Vuln Validator: Confirm findings and generate PoCs"""
        if not self.llm:
            return {"error": "AI not initialized", "validated": False}
        
        prompt = f"""Analyze this potential vulnerability for false positive detection:

Vulnerability: {vuln_data.get('type', 'Unknown')}
Endpoint: {vuln_data.get('url', 'N/A')}
Evidence: {vuln_data.get('evidence', 'N/A')}

Determine:
1. Is this a true positive? (confidence 0-100%)
2. Severity (Critical/High/Medium/Low)
3. Impact (what can attacker do?)
4. {f'PoC steps to reproduce' if poc_enabled else 'Quick validation check'}
5. Estimated bounty range

Return JSON: {{"is_valid": true/false, "confidence": 85, "severity": "High", "impact": "...", "poc": "...", "bounty_estimate": "$1000-3000"}}"""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            result = json.loads(response.content.strip('```json').strip('```'))
            
            # Generate actual PoC if enabled and Docker available
            if poc_enabled and result.get('is_valid') and self.docker_client:
                result['poc_script'] = self._generate_poc_script(vuln_data, result)
            
            return result
        except Exception as e:
            return {"error": str(e), "validated": False}
    
    def _generate_poc_script(self, vuln_data: Dict, analysis: Dict) -> str:
        """Generate executable PoC script"""
        vuln_type = vuln_data.get('type', '').lower()
        url = vuln_data.get('url', '')
        
        if 'sqli' in vuln_type:
            return f"""#!/bin/bash
# SQLi PoC for {url}
# AUTOMATED - TEST IN SANDBOX ONLY

sqlmap -u "{url}" --batch --random-agent --level=2 --risk=2
"""
        elif 'xss' in vuln_type:
            param = vuln_data.get('param', 'q')
            return f"""#!/bin/bash
# XSS PoC for {url}
# AUTOMATED - TEST IN SANDBOX ONLY

curl "{url}?{param}=<script>alert(document.domain)</script>" -H "User-Agent: BountyBot"
"""
        elif 'idor' in vuln_type:
            return f"""#!/usr/bin/env python3
# IDOR PoC for {url}
import requests

# Test accessing other user resources
for user_id in range(1, 100):
    r = requests.get(f"{url}/{{user_id}}")
    if r.status_code == 200:
        print(f"[+] Accessible: {{user_id}}")
"""
        
        return "# PoC generation not available for this vuln type"
    
    def generate_report(self, recon_data: Dict, ai_findings: Dict) -> str:
        """Report Weaver: Create bounty-ready markdown report"""
        if not self.llm:
            return "# Asura AI Report\n\nAI not available - using template report"
        
        prompt = f"""Generate a professional bug bounty report from this reconnaissance data:

Recon Summary:
- Subdomains: {recon_data.get('subdomains', 0)}
- Alive hosts: {recon_data.get('alive_hosts', 0)}
- Endpoints: {recon_data.get('endpoints', 0)}
- Vulnerabilities found: {recon_data.get('vulns', 0)}

AI Findings:
{json.dumps(ai_findings, indent=2)}

Create a markdown report with:
1. Executive Summary (3-5 sentences for quick review)
2. Critical Findings (with CVSS scores)
3. Attack Surface Analysis
4. Prioritized Recommendations
5. PoC Scripts (if available)
6. Remediation Steps

Use professional tone suitable for HackerOne/Bugcrowd submission."""

        try:
            response = self.llm.invoke([HumanMessage(content=prompt)])
            return response.content
        except:
            return "# Report generation failed"


class AsuraAI:
    """Enhanced Asura with AI-powered analysis"""
    
    def __init__(self, target, targets_file, output_dir, threads, passive_only, 
                 stealth, ai_enabled, poc_enabled, instruction, credentials, 
                 model, non_interactive):
        
        # Original Asura params
        self.target = target
        self.targets_file = targets_file
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.passive_only = passive_only
        self.stealth = stealth
        self.domains = []
        
        # AI enhancements
        self.ai_enabled = ai_enabled
        self.poc_enabled = poc_enabled
        self.custom_instruction = instruction
        self.credentials = credentials
        self.non_interactive = non_interactive
        
        # Initialize AI agents
        self.ai_agents = None
        if ai_enabled and HAS_AI:
            api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
            self.ai_agents = AIAgents(model_name=model, api_key=api_key)
        
        # Setup directories
        self.setup_directories()
        self.print_banner()
    
    def setup_directories(self):
        """Create organized output directory structure"""
        dirs = [
            'subdomains', 'alive', 'screenshots', 'ports', 'vulnerabilities',
            'endpoints', 'parameters', 'js', 'nuclei', 'technologies',
            'cloud', 'historical', 'reports'
        ]
        
        # Add AI-specific directories
        if self.ai_enabled:
            dirs.extend(['ai/agent_logs', 'ai/poc_exploits', 'artifacts'])
        
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        
        self.log(f"Created output directory: {self.output_dir}", Colors.GREEN)
    
    def print_banner(self):
        banner = f"""
{Colors.PURPLE}{Colors.BOLD}
    ___   _____ __  ______  ___     ___    ____
   /   | / ___// / / / __ \\/   |  /   |  /  _/
  / /| | \\__ \\/ / / / /_/ / /| |  / /| |  / /  
 / ___ |___/ / /_/ / _, _/ ___ | / ___ |_/ /   
/_/  |_/____/\\____/_/ |_/_/  |_|/_/  |_/___/   
                                
{Colors.END}{Colors.GREEN}Autonomous AI Reconnaissance Framework{Colors.END}
{Colors.CYAN}Powered by AI Agents • Built for Bug Bounty Hunters{Colors.END}
{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
"""
        if self.ai_enabled:
            banner += f"{Colors.PURPLE}🧠 AI Mode: ENABLED | Model: {os.getenv('ASURA_LLM', 'gpt-4o')}{Colors.END}\n"
        if self.poc_enabled:
            banner += f"{Colors.YELLOW}🔬 PoC Generation: ENABLED{Colors.END}\n"
        
        print(banner)
    
    def log(self, message, color=Colors.CYAN):
        """Formatted logging"""
        if self.non_interactive and color == Colors.YELLOW:
            return  # Skip non-critical logs in CI mode
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}{Colors.END}")
    
    def run_command(self, cmd, output_file=None, silent=False):
        """Execute shell command safely"""
        try:
            if not silent and not self.non_interactive:
                self.log(f"Running: {cmd[:100]}...", Colors.YELLOW)
            
            if output_file:
                with open(output_file, 'w') as f:
                    result = subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.PIPE, timeout=3600)
            else:
                result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
            
            return result.returncode == 0
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
    
    # Original Asura phases (simplified - same as before)
    def subdomain_enumeration(self):
        """Phase 1: Comprehensive subdomain enumeration"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 1: SUBDOMAIN ENUMERATION", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        targets = ' -d '.join(self.domains)
        all_subs = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        
        # Run tools (same as original)
        subfinder_out = self.output_dir / 'subdomains' / 'subfinder.txt'
        self.run_command(f"subfinder -d {targets} -all -recursive -silent -o {subfinder_out}")
        
        amass_out = self.output_dir / 'subdomains' / 'amass.txt'
        self.run_command(f"amass enum -d {targets} -passive -silent -o {amass_out}")
        
        # Merge
        self.run_command(f"cat {self.output_dir}/subdomains/*.txt 2>/dev/null | sort -u > {all_subs}")
        
        # AI Analysis
        if self.ai_enabled and self.ai_agents:
            self.log("🧠 AI analyzing subdomains...", Colors.PURPLE)
            with open(all_subs, 'r') as f:
                subs = [line.strip() for line in f if line.strip()]
            
            analysis = self.ai_agents.analyze_subdomains(subs, self.custom_instruction)
            
            # Save AI insights
            with open(self.output_dir / 'ai' / 'subdomain_analysis.json', 'w') as f:
                json.dump(analysis, f, indent=2)
            
            if analysis.get('high_priority'):
                self.log(f"🎯 High-priority targets: {len(analysis['high_priority'])}", Colors.GREEN)
        
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
        
        cmd = f"cat {all_subs} | httpx -silent -ports 80,443,8080,8000,8888,8443 -threads {self.threads} -o {alive_file}"
        self.run_command(cmd)
        
        with open(alive_file, 'r') as f:
            count = len(f.readlines())
        self.log(f"Found {count} alive hosts", Colors.GREEN)
    
    def endpoint_discovery(self):
        """Phase 5: Crawling and endpoint discovery with AI enhancement"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 5: ENDPOINT DISCOVERY", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        endpoints_file = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        
        # Katana crawling
        self.run_command(f"cat {alive_file} | katana -silent -d 6 -jc -f qurl -c {self.threads} -o {endpoints_file}")
        
        # Waybackurls
        wayback_file = self.output_dir / 'historical' / 'wayback.txt'
        self.run_command(f"cat {alive_file} | waybackurls 2>/dev/null | tee {wayback_file} | anew {endpoints_file}")
        
        # AI Analysis of endpoints
        if self.ai_enabled and self.ai_agents:
            self.log("🧠 AI analyzing endpoints for vulnerabilities...", Colors.PURPLE)
            with open(endpoints_file, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()][:500]  # Limit for API
            
            analysis = self.ai_agents.analyze_endpoints(endpoints)
            
            # Save prioritized targets
            prioritized_file = self.output_dir / 'ai' / 'prioritized_targets.json'
            with open(prioritized_file, 'w') as f:
                json.dump(analysis, f, indent=2)
            
            self.log(f"🎯 AI found {len(analysis.get('idor_candidates', []))} IDOR candidates", Colors.GREEN)
            self.log(f"🎯 AI found {len(analysis.get('injection_points', []))} injection points", Colors.GREEN)
        
        with open(endpoints_file, 'r') as f:
            count = len(f.readlines())
        self.log(f"Discovered {count} unique endpoints", Colors.GREEN)
    
    def vulnerability_scanning(self):
        """Phase 9: Automated vulnerability detection with AI validation"""
        self.log("="*60, Colors.HEADER)
        self.log("PHASE 9: VULNERABILITY SCANNING", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        nuclei_file = self.output_dir / 'nuclei' / 'vulnerabilities.txt'
        nuclei_json = self.output_dir / 'nuclei' / 'vulnerabilities.json'
        
        # Nuclei scan
        cmd = f"cat {alive_file} | nuclei -silent -c {self.threads} -severity critical,high,medium -json -o {nuclei_json}"
        if self.stealth:
            cmd += " -rate-limit 10"
        
        self.run_command(cmd)
        
        # AI Validation
        if self.ai_enabled and self.ai_agents and os.path.exists(nuclei_json):
            self.log("🧠 AI validating vulnerabilities and generating PoCs...", Colors.PURPLE)
            
            validated_vulns = []
            with open(nuclei_json, 'r') as f:
                for line in f:
                    try:
                        vuln = json.loads(line)
                        validation = self.ai_agents.validate_vulnerability(
                            {
                                'type': vuln.get('info', {}).get('name', ''),
                                'url': vuln.get('matched-at', ''),
                                'evidence': vuln.get('matcher-name', '')
                            },
                            poc_enabled=self.poc_enabled
                        )
                        
                        if validation.get('is_valid') and validation.get('confidence', 0) > 70:
                            vuln['ai_validation'] = validation
                            validated_vulns.append(vuln)
                            
                            # Save PoC if generated
                            if validation.get('poc_script'):
                                poc_file = self.output_dir / 'ai' / 'poc_exploits' / f"poc_{len(validated_vulns)}.sh"
                                with open(poc_file, 'w') as pf:
                                    pf.write(validation['poc_script'])
                                os.chmod(poc_file, 0o755)
                    except:
                        continue
            
            # Save validated vulns
            with open(self.output_dir / 'ai' / 'validated_vulns.json', 'w') as f:
                json.dump(validated_vulns, f, indent=2)
            
            self.log(f"✅ AI validated {len(validated_vulns)} true positives", Colors.GREEN)
            
            if self.poc_enabled:
                self.log(f"🔬 Generated {len(validated_vulns)} PoC scripts", Colors.GREEN)
    
    def generate_ai_report(self):
        """Generate comprehensive AI-powered report"""
        if not self.ai_enabled or not self.ai_agents:
            return
        
        self.log("="*60, Colors.HEADER)
        self.log("GENERATING AI REPORT", Colors.HEADER)
        self.log("="*60, Colors.HEADER)
        
        # Gather recon data
        recon_data = {}
        
        all_subs = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        if all_subs.exists():
            with open(all_subs) as f:
                recon_data['subdomains'] = len(f.readlines())
        
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        if alive_file.exists():
            with open(alive_file) as f:
                recon_data['alive_hosts'] = len(f.readlines())
        
        endpoints_file = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        if endpoints_file.exists():
            with open(endpoints_file) as f:
                recon_data['endpoints'] = len(f.readlines())
        
        # Load AI findings
        ai_findings = {}
        validated_file = self.output_dir / 'ai' / 'validated_vulns.json'
        if validated_file.exists():
            with open(validated_file) as f:
                ai_findings['validated_vulns'] = json.load(f)
                recon_data['vulns'] = len(ai_findings['validated_vulns'])
        
        prioritized_file = self.output_dir / 'ai' / 'prioritized_targets.json'
        if prioritized_file.exists():
            with open(prioritized_file) as f:
                ai_findings['prioritized'] = json.load(f)
        
        # Generate report
        self.log("🧠 AI generating bounty-ready report...", Colors.PURPLE)
        report_content = self.ai_agents.generate_report(recon_data, ai_findings)
        
        # Save report
        report_file = self.output_dir / 'reports' / f'ai_hunt_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        # Generate HackerOne export
        h1_export = {
            "title": f"Multiple Vulnerabilities in {', '.join(self.domains)}",
            "severity": "high",
            "discovered": datetime.now().isoformat(),
            "vulnerabilities": ai_findings.get('validated_vulns', [])[:10],  # Top 10
            "asset": self.domains[0] if self.domains else "N/A"
        }
        
        h1_file = self.output_dir / 'reports' / 'hackerone_export.json'
        with open(h1_file, 'w') as f:
            json.dump(h1_export, f, indent=2)
        
        self.log(f"📄 AI report saved: {report_file}", Colors.GREEN)
        self.log(f"📤 HackerOne export: {h1_file}", Colors.GREEN)
    
    def run(self):
        """Execute complete reconnaissance pipeline with AI enhancements"""
        start_time = time.time()
        
        self.load_targets()
        
        # Execute phases
        phases = [
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("Alive Check", self.alive_check),
            ("Endpoint Discovery", self.endpoint_discovery),
            ("Vulnerability Scanning", self.vulnerability_scanning),
        ]
        
        for phase_name, phase_func in phases:
            try:
                phase_func()
            except KeyboardInterrupt:
                self.log("\n\nScan interrupted by user", Colors.RED)
                if not self.non_interactive:
                    sys.exit(1)
                return
            except Exception as e:
                self.log(f"Error in {phase_name}: {str(e)}", Colors.RED)
                continue
        
        # Generate AI report
        if self.ai_enabled:
            self.generate_ai_report()
        
        elapsed = time.time() - start_time
        self.log(f"\n{'='*60}", Colors.GREEN)
        self.log(f"{'AI-POWERED ' if self.ai_enabled else ''}RECON COMPLETED IN {elapsed/60:.2f} MINUTES", Colors.GREEN)
        self.log(f"{'='*60}\n", Colors.GREEN)
        
        # Exit code for CI/CD
        if self.non_interactive:
            # Check for critical vulns
            validated_file = self.output_dir / 'ai' / 'validated_vulns.json'
            if validated_file.exists():
                with open(validated_file) as f:
                    vulns = json.load(f)
                    critical = [v for v in vulns if v.get('ai_validation', {}).get('severity') == 'Critical']
                    if critical:
                        sys.exit(1)  # Non-zero exit for CI alerts


def main():
    parser = argparse.ArgumentParser(
        description='Asura AI - Autonomous AI Reconnaissance Framework for Bug Bounty',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic recon (original):
    python3 asura_ai.py -d example.com -o output
  
  AI-powered hunt with PoCs:
    python3 asura_ai.py -d example.com -o output --ai --poc
  
  Multiple domains with custom instruction:
    python3 asura_ai.py -l domains.txt -o output --ai --instruction "Focus on payment endpoints"
  
  Stealth + Authenticated scan:
    python3 asura_ai.py -d target.com -o output --ai --stealth --creds "user:pass"
  
  Headless for CI/CD:
    python3 asura_ai.py -n -d target.com -o output --ai --poc
        '''
    )
    
    # Original flags
    parser.add_argument('-d', '--domain', help='Single target domain')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-o', '--output', default='output', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--passive', action='store_true', help='Passive reconnaissance only')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode with rate limiting')
    
    # AI Enhancement flags
    parser.add_argument('--ai', action='store_true', help='Enable AI agent swarm for analysis')
    parser.add_argument('--poc', action='store_true', help='Generate and validate PoCs in sandbox')
    parser.add_argument('--instruction', help='Custom instruction for AI agents')
    parser.add_argument('--creds', help='Authentication credentials (user:pass or token:xyz)')
    parser.add_argument('-n', '--non-interactive', action='store_true', help='Headless mode for CI/CD')
    parser.add_argument('--model', default='gpt-4o', help='LLM model (default: gpt-4o)')
    
    args = parser.parse_args()
    
    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)
    
    # Check AI dependencies
    if args.ai and not HAS_AI:
        print(f"{Colors.RED}Error: AI mode requires additional dependencies{Colors.END}")
        print(f"{Colors.YELLOW}Install with: pip install langchain-openai langchain-anthropic langchain-community docker{Colors.END}")
        sys.exit(1)
    
    # Validate model/API key
    if args.ai:
        model = os.getenv('ASURA_LLM', args.model)
        api_key = os.getenv('LLM_API_KEY') or os.getenv('OPENAI_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
        
        if not api_key and 'ollama' not in model.lower():
            print(f"{Colors.RED}Error: No API key found{Colors.END}")
            print(f"{Colors.YELLOW}Set environment variable: export LLM_API_KEY='your-key'{Colors.END}")
            sys.exit(1)
    
    # Initialize and run Asura AI
    asura = AsuraAI(
        target=args.domain,
        targets_file=args.list,
        output_dir=args.output,
        threads=args.threads,
        passive_only=args.passive,
        stealth=args.stealth,
        ai_enabled=args.ai,
        poc_enabled=args.poc,
        instruction=args.instruction,
        credentials=args.creds,
        model=args.model,
        non_interactive=args.non_interactive
    )
    
    asura.run()


if __name__ == '__main__':
    main()