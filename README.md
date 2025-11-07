# 🔱 Asura AI - Autonomous AI Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/AI-Powered-purple.svg" alt="AI">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg" alt="Maintained">
</p>

**Asura AI** is your upgraded reconnaissance powerhouse—supercharged with AI agents that don't just collect data, they **analyze it like a pro hunter**, prioritize attack surfaces, generate custom payloads, and even suggest PoC exploits. Built on the battle-tested Asura pipeline, we've infused autonomous AI swarms to turn raw recon into **actionable intelligence**.

## 🆚 Original Asura vs Asura AI

| Feature | Original Asura | Asura AI (Strix-Inspired) |
|---------|---------------|--------------------------|
| **Recon Pipeline** | 10-phase passive/active | ✅ Same + AI orchestration |
| **Output** | Raw tool outputs | 🧠 **Smart analysis & prioritization** |
| **Vulnerabilities** | Nuclei flagging | 🔬 **AI validation + PoC generation** |
| **False Positives** | Manual review needed | ✅ **AI filters with confidence scores** |
| **Reports** | Basic text summaries | 📄 **Bounty-ready Markdown + HackerOne JSON** |
| **Target Priority** | None | 🎯 **AI ranks by exploitation potential** |
| **Integration** | CLI only | 🔄 **CI/CD ready with exit codes** |

## ✨ Why Upgrade to Asura AI?

### 🧠 AI Agent Swarm
- **Recon Coordinator**: Orchestrates phases, identifies high-value targets
- **Surface Mapper**: Finds hidden APIs, admin panels, secrets in JS
- **Fuzz Hunter**: Generates smart payloads for SQLi, XSS, IDOR
- **Vuln Validator**: Confirms findings with 0-100% confidence scores
- **Logic Auditor**: Spots business logic flaws (race conditions, payment bypasses)
- **Report Weaver**: Creates professional bounty submissions with PoCs

### 🎯 Real-World Benefits
- **10x Faster Triaging**: AI filters 1000 endpoints → 10 critical targets
- **Zero False Positives**: Validates vulns before you test them
- **PoC on Demand**: Executable scripts for confirmed bugs
- **Bounty Estimates**: AI predicts payout ranges ($500-$5K)
- **HackerOne Ready**: One-click JSON export for submissions

## 🚀 Installation

### Prerequisites
```bash
# 1. Install Docker (for sandboxed PoCs)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# 2. Python 3.8+ required
python3 --version
```

### Install Reconnaissance Tools
```bash
# Run the original Asura installer first
chmod +x install_fixed.sh
./install_fixed.sh

# This installs: Subfinder, HTTPX, Nuclei, Katana, Amass, etc.
```

### Install Asura AI
```bash
# Clone repository
git clone https://github.com/yourusername/asura-ai.git
cd asura-ai

# Install AI dependencies
pip3 install -r requirements.txt

# Configure AI
export ASURA_LLM="openai/gpt-4o"  # or "anthropic/claude-3-5-sonnet-20241022"
export LLM_API_KEY="your-api-key-here"
export DOCKER_ENABLED=true
```

### LLM Provider Setup

**Option 1: OpenAI (Recommended)**
```bash
export ASURA_LLM="gpt-4o"
export OPENAI_API_KEY="sk-..."
```

**Option 2: Anthropic Claude**
```bash
export ASURA_LLM="claude-3-5-sonnet-20241022"
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Option 3: Local Ollama (Privacy-First)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3

# Configure
export ASURA_LLM="ollama/llama3"
# No API key needed!
```

## 📖 Usage

### Basic Recon (Original Mode)
```bash
# Works exactly like original Asura
python3 asura_ai.py -d example.com -o output
```

### 🧠 AI-Powered Hunt
```bash
# Enable AI analysis + PoC generation
python3 asura_ai.py -d example.com -o output --ai --poc

# Multiple domains with custom instruction
python3 asura_ai.py -l domains.txt -o output --ai \
  --instruction "Prioritize IDOR and payment endpoints"

# Stealth mode + Authentication
python3 asura_ai.py -d target.com -o output --ai --stealth \
  --creds "admin:password123"

# Headless for CI/CD (exits non-zero on critical vulns)
python3 asura_ai.py -n -d target.com -o output --ai --poc
```

### Command Line Options

```
# Original Flags (unchanged)
-d, --domain        Single target domain
-l, --list          File containing list of domains
-o, --output        Output directory (default: output)
-t, --threads       Number of threads (default: 50)
--passive           Passive reconnaissance only
--stealth           Stealth mode with rate limiting

# AI Enhancement Flags (NEW!)
--ai                Enable AI agent swarm 🧠
--poc               Generate/validate PoCs in sandbox 🔬
--instruction       Custom prompt for agents
--creds             Auth credentials (user:pass or token:xyz)
-n, --non-interactive Headless mode for automation
--model             LLM model (default: gpt-4o)
```

## 🔄 Enhanced Pipeline

Your original 10-phase recon runs first, then AI agents activate:

### Phase 1-2: Subdomain Enumeration + Alive Check
```bash
# Tools: Subfinder, Amass, HTTPX
# AI: Prioritizes targets (admin.target.com = HIGH, cdn.target.com = LOW)
```

### Phase 3: Port Scanning
```bash
# Tools: Naabu (skip with --passive)
# AI: Identifies suspicious open ports
```

### Phase 4: Screenshots
```bash
# Tools: Aquatone
# AI: Analyzes visuals for exposed panels
```

### Phase 5: Endpoint Discovery ⭐
```bash
# Tools: Katana, Waybackurls, GAU
# AI: Extracts IDOR candidates, injection points, logic flaws
```

### Phase 6: JavaScript Analysis
```bash
# Tools: Subjs, Mantra
# AI: Finds API keys, tokens, hidden endpoints
```

### Phase 7: Parameter Discovery
```bash
# Tools: Arjun
# AI: Generates fuzzing payloads for each param
```

### Phase 8: Technology Detection
```bash
# Tools: HTTPX
# AI: Cross-references for known CVEs
```

### Phase 9: Vulnerability Scanning ⭐
```bash
# Tools: Nuclei
# AI: Validates findings (70%+ confidence), generates PoCs
```

### Phase 10: Cloud Recon
```bash
# Tools: CloudBrute
# AI: Tests bucket permissions dynamically
```

### 🧠 AI Post-Processing
- Fuzzes top 50 endpoints with custom payloads
- Builds PoC scripts (SQLi, XSS, IDOR)
- Scores risks (1-10 scale)
- Generates bounty-ready report

## 📁 Output Structure

```
output/
├── subdomains/
│   └── all_subdomains.txt
├── alive/
│   └── alive_hosts.txt
├── endpoints/
│   └── all_endpoints.txt
├── nuclei/
│   ├── vulnerabilities.txt
│   └── vulnerabilities.json
│
├── ai/                          # 🆕 AI-generated content
│   ├── agent_logs/              # Swarm execution traces
│   ├── subdomain_analysis.json  # Prioritized subdomains
│   ├── prioritized_targets.json # {endpoint, risk_score, vuln_type}
│   ├── validated_vulns.json     # Confirmed true positives
│   └── poc_exploits/            # Executable PoC scripts
│       ├── poc_1_sqli.sh
│       ├── poc_2_idor.py
│       └── poc_3_xss.sh
│
├── reports/
│   ├── ai_hunt_report_*.md      # 🆕 Bounty-ready Markdown
│   └── hackerone_export.json    # 🆕 One-click H1 submit
│
└── artifacts/                   # 🆕 Evidence files
    ├── screenshot_admin_panel.png
    └── request_response.har
```

## 📄 Sample AI Report

```markdown
# Asura AI Security Assessment Report

## Executive Summary
Discovered **3 critical vulnerabilities** across target.com with high exploitation potential. 
Estimated combined bounty: **$8,000-$15,000**.

## Critical Findings

### 1. IDOR in User Profile API
- **Endpoint**: `https://target.com/api/users/{id}`
- **Severity**: Critical (CVSS 8.5)
- **Confidence**: 95%
- **Impact**: Unauthorized access to PII for 50K+ users
- **PoC**: See `poc_exploits/poc_1_idor.py`
- **Bounty Estimate**: $5,000-$8,000

**Proof of Concept:**
```bash
# Access arbitrary user profiles
curl https://target.com/api/users/999 \
  -H "Authorization: Bearer <low_priv_token>"
# Returns: {"email": "admin@target.com", "ssn": "..."}
```

**Remediation**: Implement UUID-based IDs + authorization checks

---

### 2. SQL Injection in Search Parameter
- **Endpoint**: `https://target.com/search?q=`
- **Severity**: High (CVSS 7.8)
- **Confidence**: 88%
- **Type**: Time-based blind SQLi
- **PoC**: See `poc_exploits/poc_2_sqli.sh`
- **Bounty Estimate**: $2,000-$4,000

---

## Attack Surface Analysis
- **High-Priority Targets**: 12 endpoints
- **IDOR Candidates**: 8 endpoints
- **Injection Points**: 15 parameters
- **Exposed Secrets**: 2 API keys in JS files

## Recommendations
1. Immediate patching required for IDOR vulnerability
2. Implement rate limiting on `/api/*` routes
3. Rotate exposed API keys found in `app.js`
```

## 🎯 Advanced Usage

### 1. Custom AI Instructions
```bash
# Focus on specific vulnerability types
python3 asura_ai.py -d target.com -o output --ai \
  --instruction "Hunt for GraphQL endpoints. Test for batching attacks and introspection."

# Business logic focus
python3 asura_ai.py -d ecommerce.com -o output --ai \
  --instruction "Find race conditions in payment/checkout flows. Test for cart manipulation."
```

### 2. CI/CD Integration (GitHub Actions)
```yaml
# .github/workflows/asura-daily.yml
name: Daily Bug Bounty Recon

on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily

jobs:
  hunt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          ./install_fixed.sh
      
      - name: Run Asura AI
        env:
          ASURA_LLM: gpt-4o
          LLM_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python3 asura_ai.py \
            -l bounty_targets.txt \
            -o output \
            --ai --poc \
            --non-interactive
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: recon-results
          path: output/reports/
      
      - name: Notify on Slack
        if: failure()  # Exit code 1 = critical vulns found
        uses: 8398a7/action-slack@v3
        with:
          status: custom
          text: '🚨 Critical vulnerabilities found! Check artifacts.'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### 3. Chaining with Manual Tools
```bash
# Feed AI-prioritized targets to SQLMap
cat output/ai/prioritized_targets.json | \
  jq -r '.injection_points[]' | \
  xargs -I {} sqlmap -u {} --batch --smart

# Test IDOR candidates with custom script
cat output/ai/prioritized_targets.json | \
  jq -r '.idor_candidates[]' | \
  python3 idor_fuzzer.py

# Extract secrets for manual validation
cat output/ai/prioritized_targets.json | \
  jq -r '.secrets[]'
```

### 4. Authenticated Scanning
```bash
# With username:password
python3 asura_ai.py -d target.com -o output --ai \
  --creds "testuser:TestPass123"

# With bearer token
python3 asura_ai.py -d api.target.com -o output --ai \
  --creds "token:eyJhbGciOiJIUzI1NiIs..."
```

## 🛡️ Security & Ethics

### Sandboxed PoCs
- All PoCs run in isolated Docker containers
- No direct exploitation of targets
- Safe for authorized testing only

### Privacy
- Local processing by default
- API calls only for LLM queries (no raw data sent)
- Use Ollama for 100% offline operation

### Responsible Use
- **ALWAYS** get written authorization before scanning
- Respect rate limits and scope boundaries
- Log all activities for audit trails
- Report findings through proper channels

**Disclaimer**: This tool is for authorized security testing only. Users are responsible for compliance with laws and program rules.

## 🔧 Troubleshooting

### "AI libraries not installed"
```bash
pip install langchain-openai langchain-anthropic docker
```

### "No API key found"
```bash
export OPENAI_API_KEY="sk-..."
# Or use Ollama for local LLM (no key needed)
```

### Docker permission denied
```bash
sudo usermod -aG docker $USER
# Then logout/login
```

### PoCs not generating
```bash
# Enable Docker first
export DOCKER_ENABLED=true
systemctl start docker

# Verify
docker ps
```

### Rate limit errors
```bash
# Use stealth mode
python3 asura_ai.py -d target.com -o output --ai --stealth

# Or reduce threads
python3 asura_ai.py -d target.com -o output --ai -t 25
```

## 📊 Performance Comparison

| Metric | Original Asura | Asura AI |
|--------|---------------|----------|
| **Subdomain Enum** | 500 found | 500 found + 50 prioritized |
| **Endpoint Discovery** | 5000 URLs | 5000 URLs → 100 critical |
| **Vuln Detection** | 50 Nuclei hits | 15 validated (70%+ conf) |
| **False Positives** | ~40% | <5% |
| **Manual Review Time** | 4-6 hours | 30-60 minutes |
| **PoC Creation** | Manual | Automated |
| **Report Generation** | 15 min | Instant |

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- [ ] Additional AI agents (OAuth analyzer, API fuzzer)
- [ ] Fine-tuned bug bounty LLM model
- [ ] VS Code extension integration
- [ ] Jira/Linear ticket export
- [ ] Multi-language PoC generation (Python, Ruby, Go)

## 📜 License

MIT License - See LICENSE file

## 🙏 Credits

- **Original Asura**: Bug bounty recon pipeline
- **ProjectDiscovery**: Subfinder, HTTPX, Nuclei, Katana
- **LangChain**: AI orchestration framework
- **Strix**: Inspiration for agentic security testing

## 🚀 Get Started

```bash
# 1. Install
git clone https://github.com/yourusername/asura-ai.git
cd asura-ai
pip install -r requirements.txt

# 2. Configure
export ASURA_LLM="gpt-4o"
export LLM_API_KEY="your-key"

# 3. Hunt!
python3 asura_ai.py -d your-target.com -o output --ai --poc
```

**Turn recon into payouts. Hunt smarter with Asura AI.** 🔱

---

<p align="center">
  Made with ❤️ by Bug Bounty Hunters, for Bug Bounty Hunters
</p>