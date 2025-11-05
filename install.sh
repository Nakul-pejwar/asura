#!/bin/bash

# Asura Installation Script
# Automated setup for all required tools and dependencies

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "=================================="
echo "  ASURA INSTALLATION SCRIPT"
echo "=================================="
echo -e "${NC}"

# Function to print colored messages
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please do not run this script as root"
    exit 1
fi

# Check OS
print_status "Checking operating system..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_status "Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    print_status "macOS detected"
else
    print_error "Unsupported operating system"
    exit 1
fi

# Update package manager
print_status "Updating package manager..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
elif command -v brew &> /dev/null; then
    brew update
fi

# Install basic dependencies
print_status "Installing basic dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get install -y python3 python3-pip git wget curl unzip build-essential
elif command -v brew &> /dev/null; then
    brew install python3 git wget curl unzip
fi

# Install Go
if ! command -v go &> /dev/null; then
    print_status "Installing Go..."
    GO_VERSION="1.21.0"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
        rm go${GO_VERSION}.linux-amd64.tar.gz
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        wget https://go.dev/dl/go${GO_VERSION}.darwin-amd64.tar.gz
        sudo tar -C /usr/local -xzf go${GO_VERSION}.darwin-amd64.tar.gz
        rm go${GO_VERSION}.darwin-amd64.tar.gz
    fi
    
    # Set Go environment variables
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:~/go/bin
    
    print_status "Go installed successfully"
else
    print_status "Go already installed"
fi

# Create tools directory
mkdir -p ~/tools
cd ~/tools

# Install Go-based tools
print_status "Installing reconnaissance tools..."

# ProjectDiscovery tools
print_status "Installing ProjectDiscovery suite..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Tom Hudson's tools
print_status "Installing additional Go tools..."
go install -v github.com/tomnomnom/assetfinder@latest 
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/lc/subjs@latest
go install -v github.com/003random/getJS@latest

# Arjun
print_status "Installing Arjun..."
pip3 install arjun

# Mantra
print_status "Installing Mantra..."
go install github.com/MrEmpy/mantra@latest

# Install Amass
if ! command -v amass &> /dev/null; then
    print_status "Installing Amass..."
    if command -v snap &> /dev/null; then
        sudo snap install amass
    else
        go install -v github.com/owasp-amass/amass/v4/...@master
    fi
else
    print_status "Amass already installed"
fi

# Install Aquatone
if ! command -v aquatone &> /dev/null; then
    print_status "Installing Aquatone..."
    cd ~/tools
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
        unzip -q aquatone_linux_amd64_1.7.0.zip
        sudo mv aquatone /usr/local/bin/
        rm aquatone_linux_amd64_1.7.0.zip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip
        unzip -q aquatone_macos_amd64_1.7.0.zip
        sudo mv aquatone /usr/local/bin/
        rm aquatone_macos_amd64_1.7.0.zip
    fi
    
    print_status "Aquatone installed"
else
    print_status "Aquatone already installed"
fi

# Install Sublist3r
if [ ! -d "~/tools/Sublist3r" ]; then
    print_status "Installing Sublist3r..."
    cd ~/tools
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r
    pip3 install -r requirements.txt
    print_status "Sublist3r installed"
else
    print_status "Sublist3r already installed"
fi

# Install CloudBrute
if [ ! -d "~/tools/CloudBrute" ]; then
    print_status "Installing CloudBrute..."
    cd ~/tools
    git clone https://github.com/0xsha/CloudBrute.git
    cd CloudBrute
    go build
    sudo mv cloudbrute /usr/local/bin/
    print_status "CloudBrute installed"
else
    print_status "CloudBrute already installed"
fi

# Update Nuclei templates
print_status "Updating Nuclei templates..."
nuclei -update-templates -silent

# Install Python dependencies for Asura
print_status "Installing Python dependencies..."
pip3 install colorama requests

# Create symbolic link for easy access
cd ~/tools
if [ -f "asura.py" ]; then
    chmod +x asura.py
    sudo ln -sf ~/tools/asura.py /usr/local/bin/asura
    print_status "Asura command created"
fi

# Verify installations
echo ""
print_status "Verifying installations..."
echo ""

tools=(
    "subfinder"
    "httpx"
    "katana"
    "nuclei"
    "naabu"
    "assetfinder"
    "waybackurls"
    "gau"
    "subjs"
    "anew"
    "amass"
    "aquatone"
    "mantra"
    "arjun"
)

failed=0
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}✓${NC} $tool"
    else
        echo -e "${RED}✗${NC} $tool"
        ((failed++))
    fi
done

echo ""
if [ $failed -eq 0 ]; then
    print_status "All tools installed successfully!"
    echo ""
    echo -e "${CYAN}=================================="
    echo "  INSTALLATION COMPLETE!"
    echo -e "==================================${NC}"
    echo ""
    echo "You can now run Asura with:"
    echo -e "${GREEN}python3 asura.py -d example.com -o output${NC}"
    echo ""
    echo "Or if symbolic link was created:"
    echo -e "${GREEN}asura -d example.com -o output${NC}"
    echo ""
    print_warning "Please restart your terminal or run: source ~/.bashrc"
else
    print_warning "$failed tool(s) failed to install. Please check errors above."
fi

# Source bashrc
source ~/.bashrc 2>/dev/null || true

exit 0