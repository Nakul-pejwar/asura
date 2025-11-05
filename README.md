# 🔱 Asura - Advanced Bug Bounty Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg" alt="Maintained">
</p>

**Asura** is a comprehensive, automated reconnaissance framework designed specifically for bug bounty hunters. It combines multiple tools and methodologies into a streamlined pipeline for maximum coverage and efficiency.

## ✨ Features

- 🎯 **Single & Multi-Domain Support** - Scan one or multiple targets
- 🔍 **10-Phase Recon Pipeline** - Comprehensive coverage from subdomain enum to vuln scanning
- ⚡ **Multi-threaded** - Fast execution with configurable thread pools
- 🥷 **Stealth Mode** - Rate-limited scanning to avoid detection
- 📊 **Organized Output** - Clean directory structure with categorized results
- 📝 **Detailed Reports** - Automated report generation with statistics
- 🔄 **Passive & Active Modes** - Choose your engagement level

## 🚀 Installation

### Prerequisites

```bash
# Install Go (required for many tools)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Required Tools

Install all required tools with the following commands:

```bash
# Core Recon Tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Additional Tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/lc/subjs@latest
go install -v github.com/003random/getJS@latest
go install github.com/s0md3v/Arjun@latest
go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest

# Install Amass
sudo snap install amass

# Install Aquatone (Screenshot tool)
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /usr/local/bin/
rm aquatone_linux_amd64_1.7.0.zip

# Install Sublist3r
git clone https://github.com/aboul3la/Sublist3r.git ~/tools/Sublist3r
pip3 install -r ~/tools/Sublist3r/requirements.txt

# Install CloudBrute
git clone https://github.com/0xsha/CloudBrute.git
cd CloudBrute
go build

# Install anew (for deduplication)
go install -v github.com/tomnomnom/anew@latest

# Install mantra (JS analysis)
go install github.com/MrEmpy/mantra@latest

# Update Nuclei templates
nuclei -update-templates
```

### Clone Asura

```bash
git clone https://github.com/Nakul-pejwar/asura.git
cd asura
chmod +x asura.py
```

## 📖 Usage

### Basic Usage

**Single Domain Scan:**
```bash
python3 asura.py -d example.com -o output
```

**Multiple Domains:**
```bash
python3 asura.py -l domains.txt -o output
```

**With Custom Threads:**
```bash
python3 asura.py -d example.com -o output -t 100
```

**Passive Mode (No Port Scanning):**
```bash
python3 asura.py -d example.com -o output --passive
```

**Stealth Mode (Slower, Rate-Limited):**
```bash
python3 asura.py -d example.com -o output --stealth
```

### Command Line Options

```
-d, --domain        Single target domain
-l, --list          File containing list of domains (one per line)
-o, --output        Output directory (default: output)
-t, --threads       Number of threads (default: 50)
--passive           Passive reconnaissance only (no active scanning)
--stealth           Stealth mode with rate limiting
-h, --help          Show help message
```

## 🔄 Reconnaissance Pipeline

Asura executes a comprehensive 10-phase reconnaissance pipeline:

### Phase 1: Subdomain Enumeration
- **Tools:** Subfinder, Amass, Assetfinder, Sublist3r
- **Output:** All discovered subdomains merged and deduplicated

### Phase 2: Alive Host Detection
- **Tools:** HTTPX
- **Checks:** Multiple ports (80, 443, 8080, 8000, 8888, 8443)

### Phase 3: Port Scanning
- **Tools:** Naabu
- **Method:** Fast port scanning with Nmap integration (can be skipped with --passive)

### Phase 4: Screenshot Capture
- **Tools:** Aquatone
- **Purpose:** Visual reconnaissance for quick target assessment

### Phase 5: Endpoint Discovery
- **Tools:** Katana (crawler), Waybackurls, GAU
- **Scope:** Current + Historical URLs

### Phase 6: JavaScript Analysis
- **Tools:** Subjs, Mantra
- **Targets:** Extract hidden endpoints, API keys, and sensitive data from JS files

### Phase 7: Parameter Discovery
- **Tools:** Arjun, URL parsing
- **Goal:** Find hidden GET/POST parameters for testing

### Phase 8: Technology Detection
- **Tools:** HTTPX tech-detect
- **Output:** Technology stack fingerprinting (frameworks, CMS, libraries)

### Phase 9: Vulnerability Scanning
- **Tools:** Nuclei
- **Templates:** Critical, High, and Medium severity checks

### Phase 10: Cloud Storage Recon
- **Tools:** CloudBrute
- **Targets:** AWS S3, Azure Blob, GCP buckets

## 📁 Output Structure

```
output/
├── subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   ├── sublist3r.txt
│   └── all_subdomains.txt
├── alive/
│   └── alive_hosts.txt
├── ports/
│   └── open_ports.txt
├── screenshots/
│   └── [aquatone output]
├── endpoints/
│   └── all_endpoints.txt
├── parameters/
│   ├── parameters.txt
│   └── arjun_*.txt
├── js/
│   ├── js_files.txt
│   └── js_endpoints.txt
├── nuclei/
│   └── vulnerabilities.txt
├── technologies/
│   └── stack.json
├── cloud/
│   └── buckets.txt
├── historical/
│   ├── wayback.txt
│   └── gau.txt
└── reports/
    └── report_YYYYMMDD_HHMMSS.txt
```

## 🎯 Advanced Usage Tips

### 1. Create Target List
```bash
cat > targets.txt << EOF
example.com
target.com
another.com
EOF

python3 asura.py -l targets.txt -o multi_scan
```

### 2. Continuous Monitoring
Run Asura on a schedule with cron:
```bash
# Daily recon at 2 AM
0 2 * * * cd /path/to/asura && python3 asura.py -d example.com -o output_$(date +\%Y\%m\%d)
```

### 3. Filter Results
```bash
# Find XSS-prone parameters
cat output/parameters/parameters.txt | grep -E "(q=|search=|query=|s=)"

# Find SQL injection points
cat output/parameters/parameters.txt | grep -E "(id=|user=|category=)"

# Extract JavaScript endpoints
cat output/js/js_endpoints.txt | grep -i "api"
```

### 4. Integration with Other Tools
```bash
# Run SQLMap on discovered parameters
cat output/parameters/parameters.txt | while read url; do
    sqlmap -u "$url" --batch --random-agent
done

# Test XSS with Dalfox
cat output/endpoints/all_endpoints.txt | grep "=" | dalfox pipe
```

## 🛡️ Best Practices

1. **Always Verify Scope** - Ensure targets are authorized before scanning
2. **Use Stealth Mode** - For production targets, use `--stealth` flag
3. **Rate Limiting** - Respect target infrastructure with appropriate thread counts
4. **Review Results** - Automated tools may have false positives
5. **Combine Manual + Automated** - Use Asura for breadth, manual testing for depth

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New features
- Tool integrations
- Documentation improvements

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.

## 📜 License

Copyright (c) 2025 Nakul-pejwar 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



## 🙏 Credits

Asura integrates and automates many excellent open-source tools. Special thanks to:
- ProjectDiscovery Team (Subfinder, HTTPX, Nuclei, Katana, Naabu)
- OWASP Project
- All tool authors mentioned in this documentation

## 📞 Contact

- GitHub: [@Nakul-pejwar](https://github.com/Nakul-pejwar)
- Twitter: [@nakul_pejwar](https://twitter.com/nakul_pejwar)

---

**Made with ❤️ by Bug Bounty Hunters, for Bug Bounty Hunters**