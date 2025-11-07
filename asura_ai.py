#!/usr/bin/env python3
"""
Asura AI v2 - Autonomous AI Reconnaissance Framework
AI-powered bug bounty recon with intelligent agents
"""

import argparse
import subprocess
import os
import sys
import json
import re
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

# === CONFIGURATION ===
DEFAULT_MODEL = os.getenv("ASURA_LLM", "gpt-4o")
AI_RATE_LIMIT = 2  # seconds between LLM calls
MAX_RETRIES = 3

# === COLORS ===
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    PURPLE = '\033[35m'
    END = '\033[0m'

# === LOGGER ===
logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger()

# === AI IMPORTS (Optional) ===
try:
    from langchain_openai import ChatOpenAI
    from langchain_anthropic import ChatAnthropic
    from langchain_community.llms import Ollama
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.messages import HumanMessage
    from langchain_core.output_parsers import JsonOutputParser
    import docker
    HAS_AI = True
except ImportError:
    HAS_AI = False
    log.warning(f"{Colors.YELLOW}AI dependencies missing. Run: pip install -r requirements.txt{Colors.END}")

# === HELPERS ===
def extract_json(text: str) -> Dict:
    """Extract JSON from LLM response, even if wrapped in markdown"""
    text = text.strip()
    json_pattern = r'\{.*\}'
    matches = re.findall(json_pattern, text, re.DOTALL)
    for match in matches:
        try:
            return json.loads(match)
        except json.JSONDecodeError:
            continue
    try:
        return json.loads(text)
    except:
        return {"error": "Failed to parse JSON", "raw": text[:500]}

def retry_llm(func):
    def wrapper(*args, **kwargs):
        for i in range(MAX_RETRIES):
            try:
                result = func(*args, **kwargs)
                time.sleep(AI_RATE_LIMIT)
                return result
            except Exception as e:
                if i == MAX_RETRIES - 1:
                    raise e
                log.warning(f"LLM retry {i+1}/{MAX_RETRIES}: {e}")
                time.sleep(2 ** i)
    return wrapper

# === AI AGENTS ===
class AIAgents:
    def __init__(self, model_name: str = DEFAULT_MODEL, api_key: str = None):
        self.model_name = model_name
        self.llm = None
        self.docker_client = None

        if not HAS_AI:
            return

        api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")

        try:
            if "gpt" in model_name.lower() or "openai" in model_name.lower():
                self.llm = ChatOpenAI(
                    model=model_name.split("/")[-1],
                    api_key=api_key,
                    temperature=0.3,
                    model_kwargs={"response_format": {"type": "json_object"}}
                )
            elif "claude" in model_name.lower():
                self.llm = ChatAnthropic(
                    model=model_name.split("/")[-1],
                    api_key=api_key,
                    temperature=0.3
                )
            elif "ollama" in model_name.lower():
                self.llm = Ollama(model=model_name.split("/")[-1], temperature=0.3)
        except Exception as e:
            log.error(f"{Colors.RED}Failed to init LLM: {e}{Colors.END}")

        if os.getenv("DOCKER_ENABLED", "false").lower() == "true":
            try:
                self.docker_client = docker.from_env()
            except:
                pass

    @retry_llm
    def _call_llm(self, prompt: str) -> Dict:
        if not self.llm:
            return {"error": "LLM not initialized"}
        response = self.llm.invoke([HumanMessage(content=prompt)])
        return extract_json(response.content)

    def analyze_subdomains(self, subdomains: List[str], instruction: str = "") -> Dict:
        prompt = f"""You are a senior bug bounty hunter.
Subdomains: {json.dumps(subdomains[:50])}
{instruction}

Return JSON with:
- high_priority: list
- medium_priority: list
- patterns_found: list
- recommendations: list
"""
        return self._call_llm(prompt)

    def analyze_endpoints(self, endpoints: List[str], js_secrets: List[str] = None) -> Dict:
        prompt = f"""Analyze endpoints for vulnerabilities.
Endpoints: {json.dumps(endpoints[:50])}
{ f"JS Secrets: {js_secrets[:10]}" if js_secrets else "" }

Return JSON:
- idor_candidates: list
- injection_points: list
- sensitive_paths: list
- secrets: list
- logic_flaws: list
"""
        return self._call_llm(prompt)

    def generate_fuzzing_payloads(self, parameters: List[str], vuln_type: str = "all") -> Dict:
        prompt = f"""Generate fuzzing payloads for: {parameters[:20]}
Focus: {vuln_type}

Return JSON array of payloads:
[
  {{
    "param": "id",
    "type": "sqli",
    "payload": "1' OR '1'='1",
    "detection": "delay"
  }}
]
"""
        return self._call_llm(prompt)

    def validate_vulnerability(self, vuln_data: Dict, poc_enabled: bool = False) -> Dict:
        prompt = f"""Validate this vulnerability:
Type: {vuln_data.get('type')}
URL: {vuln_data.get('url')}
Evidence: {vuln_data.get('evidence')}

Return JSON:
{{
  "is_valid": true/false,
  "confidence": 85,
  "severity": "High",
  "impact": "RCE possible",
  "poc": "curl ...",
  "bounty_estimate": "$1000-5000"
}}
"""
        result = self._call_llm(prompt)
        if poc_enabled and result.get("is_valid") and self.docker_client:
            result["poc_script"] = self._generate_poc_script(vuln_data)
        return result

    def _generate_poc_script(self, vuln_data: Dict) -> str:
        url = vuln_data.get("url", "")
        vtype = vuln_data.get("type", "").lower()

        if "sqli" in vtype:
            return f"""#!/bin/bash
# SQLi PoC - SANDBOX ONLY
sqlmap -u "{url}" --batch --risk=3 --level=3 --random-agent
"""
        elif "xss" in vtype:
            param = vuln_data.get("param", "q")
            return f"""#!/bin/bash
curl "{url}?{param}=<script>alert(1)</script>" -H "User-Agent: AsuraAI"
"""
        elif "idor" in vtype:
            return f"""#!/usr/bin/env python3
import requests
for i in range(1, 50):
    r = requests.get(f"{url.replace('1', '')}{{i}}")
    if r.status_code == 200 and "private" in r.text:
        print(f"[!] IDOR: {{i}}")
"""
        return "# PoC not supported"

    def generate_report(self, recon: Dict, findings: Dict) -> str:
        prompt = f"""Write a professional bug bounty report.

Recon: {json.dumps(recon, indent=2)}
AI Findings: {json.dumps(findings, indent=2)}

Include:
1. Executive Summary
2. Critical Findings
3. Attack Surface
4. Recommendations
5. PoC Scripts
6. Remediation

Markdown format.
"""
        try:
            resp = self.llm.invoke([HumanMessage(content=prompt)])
            return resp.content
        except:
            return self._fallback_report(recon, findings)

    def _fallback_report(self, recon: Dict, findings: Dict) -> str:
        return f"""
# Asura AI Report

## Summary
- Subdomains: {recon.get('subdomains', 0)}
- Alive: {recon.get('alive_hosts', 0)}
- Endpoints: {recon.get('endpoints', 0)}
- Validated Vulns: {recon.get('vulns', 0)}

## Findings
AI analysis unavailable. Check `ai/` directory for raw data.
"""

# === MAIN ASURA CLASS ===
class AsuraAI:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        self.output_dir = Path(self.output_dir)
        self.ai_agents = None

        if self.ai_enabled and HAS_AI:
            api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
            self.ai_agents = AIAgents(model_name=self.model, api_key=api_key)

        self.setup_directories()
        self.print_banner()

    def setup_directories(self):
        dirs = [
            'subdomains', 'alive', 'screenshots', 'ports', 'vulnerabilities',
            'endpoints', 'parameters', 'js', 'nuclei', 'technologies',
            'cloud', 'historical', 'reports', 'ai/agent_logs', 'ai/poc_exploits', 'artifacts'
        ]
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        log.info(f"{Colors.GREEN}Output: {self.output_dir}{Colors.END}")

    def print_banner(self):
        banner = f"""
{Colors.PURPLE}{Colors.BOLD}
    ___   _____ __  ______  ___     ___    ____
   /   | / ___// / / / __ \\/   |  /   |  /  _/
  / /| | \\__ \\/ / / / /_/ / /| |  / /| |  / /  
 / ___ |___/ / /_/ / _, _/ ___ | / ___ |_/ /   
/_/  |_/____/\\____/_/ |_/_/  |_|/_/  |_/___/   
{Colors.END}{Colors.CYAN}AI-Powered Bug Bounty Recon{Colors.END}
"""
        if self.ai_enabled:
            banner += f"{Colors.PURPLE}Model: {self.model}{Colors.END}\n"
        if self.poc_enabled:
            banner += f"{Colors.YELLOW}PoC Generation: ON{Colors.END}\n"
        print(banner)

    def run_command(self, cmd: str, output_file: Path = None, silent: bool = False) -> bool:
        if not silent:
            log.info(f"{Colors.YELLOW}RUN: {cmd[:80]}{'...' if len(cmd)>80 else ''}{Colors.END}")
        try:
            with open(output_file, 'w') if output_file else subprocess.DEVNULL as f:
                result = subprocess.run(
                    cmd, shell=True, stdout=f, stderr=subprocess.PIPE,
                    timeout=1800, text=True
                )
            return result.returncode == 0
        except Exception as e:
            log.error(f"{Colors.RED}CMD ERROR: {e}{Colors.END}")
            return False

    def load_targets(self):
        if self.target:
            self.domains = [self.target]
        elif self.targets_file:
            path = Path(self.targets_file)
            if not path.exists():
                log.error(f"{Colors.RED}Targets file not found: {path}{Colors.END}")
                sys.exit(1)
            self.domains = [l.strip() for l in path.read_text().splitlines() if l.strip()]
        log.info(f"{Colors.GREEN}Targets: {len(self.domains)}{Colors.END}")

    def subdomain_enumeration(self):
        log.info(f"{Colors.HEADER}PHASE 1: SUBDOMAIN ENUM{Colors.END}")
        all_file = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        cmds = [
            f"subfinder -d {' -d '.join(self.domains)} -all -silent -o {self.output_dir/'subdomains'/ 'subfinder.txt'}",
            f"amass enum -d {' -d '.join(self.domains)} -passive -o {self.output_dir/'subdomains'/ 'amass.txt'}"
        ]
        for cmd in cmds:
            self.run_command(cmd, silent=True)
        self.run_command(f"cat {self.output_dir}/subdomains/*.txt 2>/dev/null | sort -u > {all_file}")
        
        subs = [l.strip() for l in all_file.read_text().splitlines() if l.strip()]
        log.info(f"{Colors.GREEN}{len(subs)} subdomains{Colors.END}")

        if self.ai_enabled and self.ai_agents:
            log.info(f"{Colors.PURPLE}AI analyzing subdomains...{Colors.END}")
            analysis = self.ai_agents.analyze_subdomains(subs, self.custom_instruction or "")
            (self.output_dir / 'ai' / 'subdomain_analysis.json').write_text(json.dumps(analysis, indent=2))

    def alive_check(self):
        log.info(f"{Colors.HEADER}PHASE 2: ALIVE CHECK{Colors.END}")
        subs = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        alive = self.output_dir / 'alive' / 'alive_hosts.txt'
        if not subs.exists():
            log.error("No subdomains found")
            return
        self.run_command(f"cat {subs} | httpx -silent -threads {self.threads} -o {alive}")
        count = len(alive.read_text().splitlines()) if alive.exists() else 0
        log.info(f"{Colors.GREEN}{count} alive hosts{Colors.END}")

    def endpoint_discovery(self):
        log.info(f"{Colors.HEADER}PHASE 5: ENDPOINT DISCOVERY{Colors.END}")
        alive = self.output_dir / 'alive' / 'alive_hosts.txt'
        endpoints = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        if not alive.exists():
            return
        self.run_command(f"cat {alive} | katana -silent -d 5 -c {self.threads} -o {endpoints}")
        self.run_command(f"cat {alive} | waybackurls | anew {endpoints}")
        
        eps = [l.strip() for l in endpoints.read_text().splitlines()[:500]] if endpoints.exists() else []
        log.info(f"{Colors.GREEN}{len(eps)} endpoints{Colors.END}")

        if self.ai_enabled and self.ai_agents:
            log.info(f"{Colors.PURPLE}AI analyzing endpoints...{Colors.END}")
            analysis = self.ai_agents.analyze_endpoints(eps)
            (self.output_dir / 'ai' / 'prioritized_targets.json').write_text(json.dumps(analysis, indent=2))

    def vulnerability_scanning(self):
        log.info(f"{Colors.HEADER}PHASE 9: VULN SCAN{Colors.END}")
        alive = self.output_dir / 'alive' / 'alive_hosts.txt'
        json_out = self.output_dir / 'nuclei' / 'vulnerabilities.json'
        if not alive.exists():
            return
        cmd = f"cat {alive} | nuclei -c {self.threads} -severity critical,high,medium -json -o {json_out}"
        if self.stealth:
            cmd += " -rl 10"
        self.run_command(cmd)

        if self.ai_enabled and self.ai_agents and json_out.exists():
            log.info(f"{Colors.PURPLE}AI validating findings...{Colors.END}")
            validated = []
            for line in json_out.read_text().splitlines():
                try:
                    vuln = json.loads(line)
                    data = {
                        'type': vuln.get('info', {}).get('name', ''),
                        'url': vuln.get('matched-at', ''),
                        'evidence': vuln.get('extracted-results', [''])[0]
                    }
                    val = self.ai_agents.validate_vulnerability(data, self.poc_enabled)
                    if val.get('is_valid') and val.get('confidence', 0) > 70:
                        vuln['ai_validation'] = val
                        validated.append(vuln)
                        if val.get('poc_script'):
                            poc_file = self.output_dir / 'ai' / 'poc_exploits' / f"poc_{len(validated)}.sh"
                            poc_file.write_text(val['poc_script'])
                            poc_file.chmod(0o755)
                except:
                    continue
            (self.output_dir / 'ai' / 'validated_vulns.json').write_text(json.dumps(validated, indent=2))
            log.info(f"{Colors.GREEN}{len(validated)} validated vulns{Colors.END}")

    def generate_ai_report(self):
        if not self.ai_enabled or not self.ai_agents:
            return
        log.info(f"{Colors.HEADER}GENERATING REPORT{Colors.END}")
        recon = {
            'subdomains': len((self.output_dir / 'subdomains' / 'all_subdomains.txt').read_text().splitlines()) if (self.output_dir / 'subdomains' / 'all_subdomains.txt').exists() else 0,
            'alive_hosts': len((self.output_dir / 'alive' / 'alive_hosts.txt').read_text().splitlines()) if (self.output_dir / 'alive' / 'alive_hosts.txt').exists() else 0,
            'endpoints': len((self.output_dir / 'endpoints' / 'all_endpoints.txt').read_text().splitlines()) if (self.output_dir / 'endpoints' / 'all_endpoints.txt').exists() else 0,
            'vulns': len(json.loads((self.output_dir / 'ai' / 'validated_vulns.json').read_text())) if (self.output_dir / 'ai' / 'validated_vulns.json').exists() else 0
        }
        findings = {}
        for f in ['prioritized_targets.json', 'validated_vulns.json']:
            path = self.output_dir / 'ai' / f
            if path.exists():
                findings[f.split('.')[0]] = json.loads(path.read_text())

        report = self.ai_agents.generate_report(recon, findings)
        report_file = self.output_dir / 'reports' / f"asura_report_{datetime.now():%Y%m%d_%H%M%S}.md"
        report_file.write_text(report)
        log.info(f"{Colors.GREEN}Report: {report_file}{Colors.END}")

    def run(self):
        start = time.time()
        self.load_targets()
        for name, func in [
            ("Subdomains", self.subdomain_enumeration),
            ("Alive", self.alive_check),
            ("Endpoints", self.endpoint_discovery),
            ("Vulns", self.vulnerability_scanning),
        ]:
            try:
                func()
            except Exception as e:
                log.error(f"{Colors.RED}{name} failed: {e}{Colors.END}")
        if self.ai_enabled:
            self.generate_ai_report()
        log.info(f"{Colors.GREEN}Done in {(time.time()-start)/60:.1f} min{Colors.END}")

# === CLI ===
def main():
    parser = argparse.ArgumentParser(description="Asura AI - AI Bug Bounty Recon")
    parser.add_argument('-d', '--domain')
    parser.add_argument('-l', '--list')
    parser.add_argument('-o', '--output', default='asura_output')
    parser.add_argument('-t', '--threads', type=int, default=50)
    parser.add_argument('--stealth', action='store_true')
    parser.add_argument('--ai', action='store_true')
    parser.add_argument('--poc', action='store_true')
    parser.add_argument('--instruction')
    parser.add_argument('--model', default=DEFAULT_MODEL)
    parser.add_argument('-n', '--non-interactive', action='store_true')

    args = parser.parse_args()
    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    if args.ai and not HAS_AI:
        log.error(f"{Colors.RED}Install AI deps: pip install langchain-openai docker{Colors.END}")
        sys.exit(1)

    AsuraAI(
        target=args.domain,
        targets_file=args.list,
        output_dir=args.output,
        threads=args.threads,
        stealth=args.stealth,
        ai_enabled=args.ai,
        poc_enabled=args.poc,
        custom_instruction=args.instruction,
        model=args.model,
        non_interactive=args.non_interactive
    ).run()

if __name__ == '__main__':
    main()