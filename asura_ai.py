#!/usr/bin/env python3
"""
Asura AI v2 - Autonomous AI Reconnaissance Framework
AI-powered bug bounty recon with intelligent agents
"""

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Coroutine, Callable
import random

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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger("AsuraAI")

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
def extract_json(text: str) -> Dict[str, Any]:
    """Extract JSON safely from text (even if inside markdown)."""
    text = text.strip()
    json_pattern = r'\{(?:[^{}]|(?R))*\}'
    matches = re.findall(json_pattern, text, re.DOTALL)
    for match in matches:
        try:
            return json.loads(match)
        except json.JSONDecodeError:
            continue
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON", "raw": text[:500]}

def read_file_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]

def write_text_file(path: Path, content: str) -> None:
    path.write_text(content)

def retry_async(max_retries: int = MAX_RETRIES, base_delay: float = AI_RATE_LIMIT):
    """Decorator for asyncio functions to retry with exponential backoff and jitter."""
    def decorator(func: Callable[..., Coroutine[Any, Any, Any]]):
        async def wrapper(*args, **kwargs):
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        log.error(f"Max retries reached. Last error: {e}")
                        raise
                    delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                    log.warning(f"Retry {attempt}/{max_retries} for {func.__name__} after error: {e} (sleeping {delay:.1f}s)")
                    await asyncio.sleep(delay)
        return wrapper
    return decorator

# === AI AGENTS ===
class AIAgents:
    def __init__(self, model_name: str = DEFAULT_MODEL, api_key: Optional[str] = None):
        self.model_name = model_name
        self.llm = None
        self.docker_client = None

        if not HAS_AI:
            log.warning("AI features disabled due to missing dependencies.")
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
            else:
                log.warning(f"Unsupported model specified: {model_name}, AI calls disabled.")
                self.llm = None
        except Exception as e:
            log.error(f"{Colors.RED}Failed to initialize LLM: {e}{Colors.END}")

        if os.getenv("DOCKER_ENABLED", "false").lower() == "true":
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                log.warning(f"Docker client initialization failed: {e}")

    @retry_async()
    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        if not self.llm:
            return {"error": "LLM not initialized"}
        # For demonstration, assuming llm.invoke_async exists; else wrap sync call accordingly
        if hasattr(self.llm, "invoke_async"):
            response = await self.llm.invoke_async([HumanMessage(content=prompt)])
        else:
            # fallback synchronous call wrapped in thread for async
            import concurrent.futures
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                response = await loop.run_in_executor(pool, lambda: self.llm.invoke([HumanMessage(content=prompt)]))
        return extract_json(response.content)

    async def analyze_subdomains(self, subdomains: List[str], instruction: str = "") -> Dict[str, Any]:
        prompt = (
            f"You are a senior bug bounty hunter.\n"
            f"Subdomains: {json.dumps(subdomains[:50])}\n"
            f"{instruction}\n\n"
            "Return JSON with:\n"
            "- high_priority: list\n"
            "- medium_priority: list\n"
            "- patterns_found: list\n"
            "- recommendations: list\n"
        )
        return await self._call_llm(prompt)

    async def analyze_endpoints(self, endpoints: List[str], js_secrets: Optional[List[str]] = None) -> Dict[str, Any]:
        prompt = (
            f"Analyze endpoints for vulnerabilities.\n"
            f"Endpoints: {json.dumps(endpoints[:50])}\n"
            f"{f'JS Secrets: {js_secrets[:10]}' if js_secrets else ''}\n\n"
            "Return JSON:\n"
            "- idor_candidates: list\n"
            "- injection_points: list\n"
            "- sensitive_paths: list\n"
            "- secrets: list\n"
            "- logic_flaws: list\n"
        )
        return await self._call_llm(prompt)

    async def generate_fuzzing_payloads(self, parameters: List[str], vuln_type: str = "all") -> Dict[str, Any]:
        prompt = (
            f"Generate fuzzing payloads for: {parameters[:20]}\n"
            f"Focus: {vuln_type}\n\n"
            "Return JSON array of payloads:\n"
            "[\n"
            "  {\n"
            '    "param": "id",\n'
            '    "type": "sqli",\n'
            '    "payload": "1\' OR \'1\'=\'1",\n'
            '    "detection": "delay"\n'
            "  }\n"
            "]\n"
        )
        return await self._call_llm(prompt)

    async def validate_vulnerability(self, vuln_data: Dict[str, Any], poc_enabled: bool = False) -> Dict[str, Any]:
        prompt = (
            f"Validate this vulnerability:\n"
            f"Type: {vuln_data.get('type')}\n"
            f"URL: {vuln_data.get('url')}\n"
            f"Evidence: {vuln_data.get('evidence')}\n\n"
            "Return JSON:\n"
            "{\n"
            '  "is_valid": true/false,\n'
            '  "confidence": 85,\n'
            '  "severity": "High",\n'
            '  "impact": "RCE possible",\n'
            '  "poc": "curl ...",\n'
            '  "bounty_estimate": "$1000-5000"\n'
            "}\n"
        )
        result = await self._call_llm(prompt)
        if poc_enabled and result.get("is_valid") and self.docker_client:
            result["poc_script"] = self._generate_poc_script(vuln_data)
        return result

    def _generate_poc_script(self, vuln_data: Dict[str, Any]) -> str:
        url = vuln_data.get("url", "")
        vtype = vuln_data.get("type", "").lower()

        if "sqli" in vtype:
            return (
                "#!/bin/bash\n"
                "# SQLi PoC - SANDBOX ONLY\n"
                f"sqlmap -u \"{url}\" --batch --risk=3 --level=3 --random-agent\n"
            )
        elif "xss" in vtype:
            param = vuln_data.get("param", "q")
            return (
                "#!/bin/bash\n"
                f"curl \"{url}?{param}=<script>alert(1)</script>\" -H \"User-Agent: AsuraAI\"\n"
            )
        elif "idor" in vtype:
            return (
                "#!/usr/bin/env python3\n"
                "import requests\n"
                "for i in range(1, 50):\n"
                f"    r = requests.get(f\"{url.replace('1', '')}{{i}}\")\n"
                "    if r.status_code == 200 and \"private\" in r.text:\n"
                "        print(f\"[!] IDOR: {i}\")\n"
            )
        return "# PoC not supported"

    async def generate_report(self, recon: Dict[str, Any], findings: Dict[str, Any]) -> str:
        prompt = (
            "Write a professional bug bounty report.\n\n"
            f"Recon: {json.dumps(recon, indent=2)}\n"
            f"AI Findings: {json.dumps(findings, indent=2)}\n\n"
            "Include:\n"
            "1. Executive Summary\n"
            "2. Critical Findings\n"
            "3. Attack Surface\n"
            "4. Recommendations\n"
            "5. PoC Scripts\n"
            "6. Remediation\n\n"
            "Markdown format.\n"
        )
        try:
            if hasattr(self.llm, "invoke_async"):
                resp = await self.llm.invoke_async([HumanMessage(content=prompt)])
            else:
                import concurrent.futures
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    resp = await loop.run_in_executor(pool, lambda: self.llm.invoke([HumanMessage(content=prompt)]))
            return resp.content
        except Exception:
            return self._fallback_report(recon, findings)

    def _fallback_report(self, recon: Dict[str, Any], findings: Dict[str, Any]) -> str:
        return (
            "# Asura AI Report\n\n"
            "## Summary\n"
            f"- Subdomains: {recon.get('subdomains', 0)}\n"
            f"- Alive: {recon.get('alive_hosts', 0)}\n"
            f"- Endpoints: {recon.get('endpoints', 0)}\n"
            f"- Validated Vulns: {recon.get('vulns', 0)}\n\n"
            "## Findings\n"
            "AI analysis unavailable. Check `ai/` directory for raw data.\n"
        )

# === MAIN ASURA CLASS ===
class AsuraAI:
    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            setattr(self, k, v)

        self.output_dir = Path(self.output_dir)
        self.ai_agents: Optional[AIAgents] = None

        if getattr(self, "ai_enabled", False) and HAS_AI:
            api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
            self.ai_agents = AIAgents(model_name=getattr(self, "model", DEFAULT_MODEL), api_key=api_key)

        self.setup_directories()
        self.print_banner()

    def setup_directories(self) -> None:
        dirs = [
            'subdomains', 'alive', 'screenshots', 'ports', 'vulnerabilities',
            'endpoints', 'parameters', 'js', 'nuclei', 'technologies',
            'cloud', 'historical', 'reports', 'ai/agent_logs', 'ai/poc_exploits', 'artifacts'
        ]
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)
        log.info(f"{Colors.GREEN}Output directory: {self.output_dir}{Colors.END}")

    def print_banner(self) -> None:
        banner = (
            f"\n{Colors.PURPLE}{Colors.BOLD}"
            "    ___   _____ __  ______  ___     ___    ____\n"
            "   /   | / ___// / / / __ \\/   |  /   |  /  _/\n"
            "  / /| | \\__ \\/ / / / /_/ / /| |  / /| |  / /  \n"
            " / ___ |___/ / /_/ / _, _/ ___ | / ___ |_/ /   \n"
            "/_/  |_/____/\\____/_/ |_/_/  |_|/_/  |_/___/   \n"
            f"{Colors.END}{Colors.CYAN}AI-Powered Bug Bounty Recon Framework{Colors.END}\n"
        )
        if getattr(self, "ai_enabled", False):
            banner += f"{Colors.PURPLE}Model: {getattr(self, 'model', DEFAULT_MODEL)}{Colors.END}\n"
        if getattr(self, "poc_enabled", False):
            banner += f"{Colors.YELLOW}PoC Generation: ON{Colors.END}\n"
        print(banner)

    def run_command(self, cmd: str, output_file: Optional[Path] = None, silent: bool = False) -> bool:
        if not silent:
            log.info(f"{Colors.YELLOW}RUNNING: {cmd[:80]}{'...' if len(cmd) > 80 else ''}{Colors.END}")
        try:
            with open(output_file, 'w') if output_file else subprocess.DEVNULL as f:
                result = subprocess.run(
                    cmd, shell=True, stdout=f, stderr=subprocess.PIPE,
                    timeout=1800, text=True
                )
            if result.returncode != 0:
                log.error(f"{Colors.RED}Command failed with code {result.returncode}: {cmd}{Colors.END}")
            return result.returncode == 0
        except Exception as e:
            log.error(f"{Colors.RED}Command execution error: {e}{Colors.END}")
            return False

    def load_targets(self) -> None:
        if getattr(self, "target", None):
            self.domains = [self.target]
        elif getattr(self, "targets_file", None):
            path = Path(self.targets_file)
            if not path.exists():
                log.error(f"{Colors.RED}Targets file not found: {path}{Colors.END}")
                sys.exit(1)
            self.domains = read_file_lines(path)
        else:
            log.error(f"{Colors.RED}No targets specified.{Colors.END}")
            sys.exit(1)
        log.info(f"{Colors.GREEN}Loaded {len(self.domains)} target(s).{Colors.END}")

    def subdomain_enumeration(self) -> None:
        log.info(f"{Colors.HEADER}PHASE 1: SUBDOMAIN ENUMERATION{Colors.END}")
        all_file = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        cmds = [
            f"subfinder -d {' -d '.join(self.domains)} -all -silent -o {self.output_dir / 'subdomains' / 'subfinder.txt'}",
            f"amass enum -d {' -d '.join(self.domains)} -passive -o {self.output_dir / 'subdomains' / 'amass.txt'}"
        ]
        for cmd in cmds:
            self.run_command(cmd, silent=True)
        # Aggregate all subdomains sorted uniquely
        combined = []
        for file_path in (self.output_dir / 'subdomains').glob('*.txt'):
            combined += read_file_lines(file_path)
        all_subs = sorted(set(combined))
        write_text_file(all_file, "\n".join(all_subs))

        log.info(f"{Colors.GREEN}{len(all_subs)} subdomains found.{Colors.END}")

        if getattr(self, "ai_enabled", False) and self.ai_agents:
            log.info(f"{Colors.PURPLE}Analyzing subdomains with AI...{Colors.END}")
            analysis = asyncio.run(self.ai_agents.analyze_subdomains(all_subs, getattr(self, "custom_instruction", "") or ""))
            write_text_file(self.output_dir / 'ai' / 'subdomain_analysis.json', json.dumps(analysis, indent=2))

    def alive_check(self) -> None:
        log.info(f"{Colors.HEADER}PHASE 2: ALIVE HOST CHECK{Colors.END}")
        all_sub_file = self.output_dir / 'subdomains' / 'all_subdomains.txt'
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        if not all_sub_file.exists():
            log.error("No subdomains available for alive check.")
            return
        self.run_command(f"cat {all_sub_file} | httpx -silent -threads {getattr(self, 'threads', 50)} -o {alive_file}")
        alive_count = len(read_file_lines(alive_file))
        log.info(f"{Colors.GREEN}{alive_count} hosts are alive.{Colors.END}")

    def endpoint_discovery(self) -> None:
        log.info(f"{Colors.HEADER}PHASE 5: ENDPOINT DISCOVERY{Colors.END}")
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        endpoints_file = self.output_dir / 'endpoints' / 'all_endpoints.txt'
        if not alive_file.exists():
            log.error("No alive hosts to enumerate endpoints.")
            return

        self.run_command(f"cat {alive_file} | katana -silent -d 5 -c {getattr(self, 'threads', 50)} -o {endpoints_file}")
        self.run_command(f"cat {alive_file} | waybackurls | anew {endpoints_file}")

        endpoints = read_file_lines(endpoints_file)[:500]
        log.info(f"{Colors.GREEN}{len(endpoints)} endpoints discovered.{Colors.END}")

        if getattr(self, "ai_enabled", False) and self.ai_agents:
            log.info(f"{Colors.PURPLE}Analyzing endpoints with AI...{Colors.END}")
            analysis = asyncio.run(self.ai_agents.analyze_endpoints(endpoints))
            write_text_file(self.output_dir / 'ai' / 'prioritized_targets.json', json.dumps(analysis, indent=2))

    def vulnerability_scanning(self) -> None:
        log.info(f"{Colors.HEADER}PHASE 9: VULNERABILITY SCANNING{Colors.END}")
        alive_file = self.output_dir / 'alive' / 'alive_hosts.txt'
        nuclei_json = self.output_dir / 'nuclei' / 'vulnerabilities.json'
        if not alive_file.exists():
            log.error("No alive hosts to scan vulnerabilities.")
            return

        cmd = f"cat {alive_file} | nuclei -c {getattr(self, 'threads', 50)} -severity critical,high,medium -json -o {nuclei_json}"
        if getattr(self, "stealth", False):
            cmd += " -rl 10"
        self.run_command(cmd)

        if getattr(self, "ai_enabled", False) and self.ai_agents and nuclei_json.exists():
            log.info(f"{Colors.PURPLE}Validating findings with AI...{Colors.END}")
            validated = []
            for line in nuclei_json.read_text().splitlines():
                try:
                    vuln = json.loads(line)
                    vuln_data = {
                        'type': vuln.get('info', {}).get('name', ''),
                        'url': vuln.get('matched-at', ''),
                        'evidence': vuln.get('extracted-results', [''])[0]
                    }
                    val = asyncio.run(self.ai_agents.validate_vulnerability(vuln_data, getattr(self, "poc_enabled", False)))
                    if val.get('is_valid') and val.get('confidence', 0) > 70:
                        vuln['ai_validation'] = val
                        validated.append(vuln)
                        if val.get('poc_script'):
                            poc_file = self.output_dir / 'ai' / 'poc_exploits' / f"poc_{len(validated)}.sh"
                            write_text_file(poc_file, val['poc_script'])
                            poc_file.chmod(0o755)
                except Exception as e:
                    log.warning(f"Failed to validate vulnerability entry: {e}")
                    continue
            write_text_file(self.output_dir / 'ai' / 'validated_vulns.json', json.dumps(validated, indent=2))
            log.info(f"{Colors.GREEN}{len(validated)} vulnerabilities validated by AI.{Colors.END}")

    def generate_ai_report(self) -> None:
        if not getattr(self, "ai_enabled", False) or not self.ai_agents:
            return
        log.info(f"{Colors.HEADER}GENERATING AI REPORT{Colors.END}")

        recon = {
            'subdomains': len(read_file_lines(self.output_dir / 'subdomains' / 'all_subdomains.txt')),
            'alive_hosts': len(read_file_lines(self.output_dir / 'alive' / 'alive_hosts.txt')),
            'endpoints': len(read_file_lines(self.output_dir / 'endpoints' / 'all_endpoints.txt')),
            'vulns': 0,
        }
        validated_vulns_path = self.output_dir / 'ai' / 'validated_vulns.json'
        if validated_vulns_path.exists():
            recon['vulns'] = len(json.loads(validated_vulns_path.read_text()))

        findings = {}
        for file_name in ['prioritized_targets.json', 'validated_vulns.json']:
            path = self.output_dir / 'ai' / file_name
            if path.exists():
                findings[file_name.rsplit('.', 1)[0]] = json.loads(path.read_text())

        report = asyncio.run(self.ai_agents.generate_report(recon, findings))
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.output_dir / 'reports' / f"asura_report_{timestamp}.md"
        write_text_file(report_file, report)
        log.info(f"{Colors.GREEN}Report saved: {report_file}{Colors.END}")

    def run(self) -> None:
        start_time = time.time()
        self.load_targets()
        phases = [
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("Alive Host Check", self.alive_check),
            ("Endpoint Discovery", self.endpoint_discovery),
            ("Vulnerability Scanning", self.vulnerability_scanning),
        ]
        for name, func in phases:
            try:
                func()
            except Exception as e:
                log.error(f"{Colors.RED}{name} phase failed: {e}{Colors.END}")

        if getattr(self, "ai_enabled", False):
            self.generate_ai_report()

        elapsed = (time.time() - start_time) / 60
        log.info(f"{Colors.GREEN}All phases complete in {elapsed:.1f} minutes.{Colors.END}")

# === CLI ===
def main() -> None:
    parser = argparse.ArgumentParser(description="Asura AI - AI Bug Bounty Recon Framework")
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-l', '--list', help='File containing list of target domains')
    parser.add_argument('-o', '--output', default='asura_output', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Concurrency threads')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--ai', action='store_true', help='Enable AI features')
    parser.add_argument('--poc', action='store_true', help='Enable PoC generation')
    parser.add_argument('--instruction', help='Custom AI instruction for analysis')
    parser.add_argument('--model', default=DEFAULT_MODEL, help='AI model name')
    parser.add_argument('-n', '--non-interactive', action='store_true', help='Non-interactive mode')

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    if args.ai and not HAS_AI:
        log.error(f"{Colors.RED}AI dependencies missing. Install with: pip install -r requirements.txt{Colors.END}")
        sys.exit(1)

    ai_enabled = args.ai and HAS_AI

    asura = AsuraAI(
        target=args.domain,
        targets_file=args.list,
        output_dir=args.output,
        threads=args.threads,
        stealth=args.stealth,
        ai_enabled=ai_enabled,
        poc_enabled=args.poc,
        custom_instruction=args.instruction,
        model=args.model,
        non_interactive=args.non_interactive,
    )
    asura.run()

if __name__ == '__main__':
    main()
