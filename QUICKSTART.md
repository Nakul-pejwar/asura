# 🚀 Asura AI Quick Start Guide

Get up and running with AI-powered bug bounty recon in **5 minutes**.

## Step 1: Install Prerequisites (2 minutes)

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Verify Python 3.8+
python3 --version

# Install Go tools
./install_fixed.sh
```

## Step 2: Setup Asura AI (1 minute)

```bash
# Clone repository
git clone https://github.com/yourusername/asura-ai.git
cd asura-ai

# Install AI dependencies
pip3 install -r requirements.txt
```

## Step 3: Configure API Key (1 minute)

Choose your LLM provider:

### Option A: OpenAI (Best Results)
```bash
export ASURA_LLM="gpt-4o"
export OPENAI_API_KEY="sk-proj-YOUR_KEY_HERE"
```

Get API key: https://platform.openai.com/api-keys

### Option B: Anthropic Claude (Alternative)
```bash
export ASURA_LLM="claude-3-5-sonnet-20241022"
export ANTHROPIC_API_KEY="sk-ant-YOUR_KEY_HERE"
```

Get API key: https://console.anthropic.com/

### Option C: Local Ollama (Free, Privacy-First)
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3

# Configure (no API key needed!)
export ASURA_LLM="ollama/llama3"
```

## Step 4: Run Your First Scan (1 minute)

### Basic Recon (No AI)
```bash
python3 asura_ai.py -d example.com -o output
```

### 🧠 AI-Powered Hunt
```bash
python3 asura_ai.py -d example.com -o output --ai --poc
```

### Check Results
```bash
# View AI report
cat output/reports/ai_hunt_report_*.md

# Check validated vulnerabilities
cat output/ai/validated_vulns.json | jq

# See PoC exploits
ls -la output/ai/poc_exploits/
```

## 🎯 Common Use Cases

### 1. Single Domain Deep Scan
```bash
python3 asura_ai.py -d target.com -o results --ai --poc \
  --instruction "Focus on IDOR and authentication bypasses"
```

### 2. Multiple Targets
```bash
# Create targets file
cat > targets.txt << EOF
target1.com
target2.com
target3.com
EOF

# Scan all
python3 asura_ai.py -l targets.txt -o multi_scan --ai
```

### 3. Stealth Mode (Low & Slow)
```bash
python3 asura_ai.py -d target.com -o stealth_scan \
  --ai --stealth -t 25
```

### 4. Authenticated Scan
```bash
python3 asura_ai.py -d target.com -o auth_scan \
  --ai --creds "user@example.com:password123"
```

### 5. Passive Recon Only (No Port Scan)
```bash
python3 asura_ai.py -d target.com -o passive --ai --passive
```

## 📊 Understanding Output

```
output/
├── reports/
│   ├── ai_hunt_report_20250107.md      ← Read this first!
│   └── hackerone_export.json           ← Submit to H1
│
├── ai/
│   ├── validated_vulns.json            ← Confirmed bugs
│   ├── prioritized_targets.json        ← High-value endpoints
│   └── poc_exploits/                   ← Test scripts
│
├── subdomains/all_subdomains.txt       ← All discovered subs
├── alive/alive_hosts.txt               ← Live targets
└── endpoints/all_endpoints.txt         ← URLs found
```

## 🔍 Next Steps

### Extract High-Priority Targets
```bash
# Get IDOR candidates
cat output/ai/prioritized_targets.json | jq '.idor_candidates[]'

# Get injection points
cat output/ai/prioritized_targets.json | jq '.injection_points[]'

# Get critical vulnerabilities
cat output/ai/validated_vulns.json | jq '.[] | select(.ai_validation.severity=="Critical")'
```

### Run PoC Scripts
```bash
# Make executable
chmod +x output/ai/poc_exploits/*

# Run IDOR PoC (in sandbox!)
./output/ai/poc_exploits/poc_1_idor.py

# Run SQLi PoC
./output/ai/poc_exploits/poc_2_sqli.sh
```

### Export for HackerOne
```bash
# Copy JSON to clipboard
cat output/reports/hackerone_export.json | pbcopy  # macOS
cat output/reports/hackerone_export.json | xclip   # Linux

# Then paste into HackerOne submission form
```

## 🐛 Troubleshooting

### "AI libraries not installed"
```bash
pip3 install langchain-openai langchain-anthropic docker
```

### "No API key found"
```bash
# Check if set
echo $OPENAI_API_KEY

# If empty, set it
export OPENAI_API_KEY="your-key-here"

# Make permanent
echo 'export OPENAI_API_KEY="your-key"' >> ~/.bashrc
source ~/.bashrc
```

### Tools not found (subfinder, httpx, etc.)
```bash
# Re-run installer
./install_fixed.sh

# Add Go bin to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

### Docker permission denied
```bash
sudo usermod -aG docker $USER
# Then logout and login again
```

### Slow scanning
```bash
# Increase threads (default: 50)
python3 asura_ai.py -d target.com -o output --ai -t 100

# Or use cached results
python3 asura_ai.py -d target.com -o output --ai --use-cache
```

## 💡 Pro Tips

1. **Start with passive mode** to understand scope:
   ```bash
   python3 asura_ai.py -d target.com -o recon --ai --passive
   ```

2. **Use custom instructions** for focused hunting:
   ```bash
   --instruction "Hunt for GraphQL introspection and batching attacks"
   ```

3. **Save API costs** with Ollama for initial runs:
   ```bash
   export ASURA_LLM="ollama/llama3"  # Free & local
   ```

4. **Chain with manual tools**:
   ```bash
   # Feed to SQLMap
   cat output/ai/prioritized_targets.json | jq -r '.injection_points[]' | xargs -I {} sqlmap -u {}
   
   # Feed to Burp Suite
   cat output/endpoints/all_endpoints.txt > burp_targets.txt
   ```

5. **Schedule daily scans**:
   ```bash
   # Add to crontab
   0 2 * * * cd /path/to/asura-ai && python3 asura_ai.py -l targets.txt -o daily_$(date +\%Y\%m\%d) --ai
   ```

## 📚 Learn More

- **Full Documentation**: See [README_AI.md](README_AI.md)
- **Configuration**: See [.env.example](.env.example)
- **CI/CD Setup**: See [.github/workflows/asura-daily.yml](.github/workflows/asura-daily.yml)
- **Troubleshooting**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 🎓 Example Workflow

Here's a complete bug bounty hunting workflow:

```bash
# Day 1: Initial recon
python3 asura_ai.py -d target.com -o day1 --ai --passive

# Day 2: Deep scan on high-priority targets
cat day1/ai/prioritized_targets.json | jq -r '.high_priority[]' > high_value.txt
python3 asura_ai.py -l high_value.txt -o day2 --ai --poc

# Day 3: Manual validation
cd day2/ai/poc_exploits
./poc_1_idor.py  # Test in sandbox
./poc_2_sqli.sh

# Day 4: Submit findings
cat day2/reports/hackerone_export.json
# Submit to HackerOne with AI-generated report
```

## 🏁 You're Ready!

```bash
# Run your first AI-powered scan
python3 asura_ai.py -d your-target.com -o my_first_hunt --ai --poc

# Watch the AI agents work their magic! 🧠✨
```

---

**Questions?** Open an issue on GitHub or check the full documentation.

**Happy Hunting! 🔱**