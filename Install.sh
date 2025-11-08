#!/bin/bash

##############################################
# 0xZan Security Toolkit - Auto Installer
# Created by: 0xZan
# Description: Automated installation script for bug bounty toolkit
##############################################

# Auto-fix line endings (in case of Windows upload issues)
sed -i 's/\r$//' "$0" 2>/dev/null
sed -i 's/\r$//' "$(dirname "$0")/organize_0xZan.sh" 2>/dev/null
sed -i 's/\r$//' "$(dirname "$0")/bountyrecon.py" 2>/dev/null

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
   ___       _____            
  / _ \__ __/__  / ___ _ ___  
 | | | \ \ /  / /_/ _ `/ _ \ 
 | |_| |> <  / /__\_,_/_//_/ 
  \___//_/\_\/____/           
                              
    Bug Bounty Security Toolkit
    Created by: 0xZan 
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Please do not run this script as root${NC}"
   echo -e "${YELLOW}[*] Run as normal user - script will ask for sudo when needed${NC}"
   exit 1
fi

# Logging
LOGFILE="install_log_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee -a "$LOGFILE")
exec 2>&1

echo -e "${GREEN}[*] Installation log: $LOGFILE${NC}\n"

# Check OS compatibility
echo -e "${BLUE}[*] Checking system compatibility...${NC}"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    echo -e "${GREEN}[✓] Detected: $PRETTY_NAME${NC}"
else
    echo -e "${RED}[!] Cannot detect OS. This script supports Kali/Ubuntu/Debian${NC}"
    exit 1
fi

# Supported OS check
if [[ "$OS" != "kali" && "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
    echo -e "${YELLOW}[!] Warning: Unsupported OS. Script designed for Kali/Ubuntu/Debian${NC}"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check internet connectivity
echo -e "\n${BLUE}[*] Checking internet connectivity...${NC}"
if ping -c 1 google.com &> /dev/null; then
    echo -e "${GREEN}[✓] Internet connection active${NC}"
else
    echo -e "${RED}[!] No internet connection detected${NC}"
    exit 1
fi

# Set installation directory to ~/0xZan
INSTALL_DIR="$HOME/0xZan"
echo -e "\n${BLUE}[*] Installation directory: $INSTALL_DIR${NC}"

# Create main directory
echo -e "${BLUE}[*] Creating main directory structure...${NC}"
mkdir -p "$INSTALL_DIR"

##############################################
# PHASE 1: System Update & Dependencies
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 1: System Update & Dependencies${NC}"
echo -e "${YELLOW}========================================${NC}\n"

echo -e "${BLUE}[*] Updating package lists...${NC}"
sudo apt update -y

echo -e "${BLUE}[*] Upgrading system packages (this may take a while)...${NC}"
sudo apt upgrade -y

echo -e "${BLUE}[*] Installing essential dependencies...${NC}"
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    golang-go \
    nmap \
    sqlmap \
    metasploit-framework \
    unzip \
    jq \
    dnsutils \
    netcat-traditional \
    parallel

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] System dependencies installed${NC}"
else
    echo -e "${RED}[!] Failed to install system dependencies${NC}"
    exit 1
fi

##############################################
# CLEANUP: Free space before continuing
##############################################

echo -e "\n${BLUE}[*] Cleaning up to free disk space...${NC}"
sudo apt autoremove -y
sudo apt clean
sudo apt autoclean
echo -e "${GREEN}[✓] Cleanup complete${NC}"

##############################################
# PHASE 2: Python Environment Setup
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 2: Python Environment Setup${NC}"
echo -e "${YELLOW}========================================${NC}\n"

echo -e "${BLUE}[*] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip --break-system-packages 2>/dev/null || python3 -m pip install --upgrade pip

echo -e "${BLUE}[*] Installing Python packages...${NC}"
pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    lxml \
    aiohttp \
    asyncio \
    python-nmap \
    colorama \
    termcolor \
    tqdm \
    pyyaml \
    jinja2 \
    click \
    tabulate \
    validators \
    dnspython \
    pycryptodome \
    urllib3 \
    certifi 2>/dev/null || \
pip3 install \
    requests \
    beautifulsoup4 \
    lxml \
    aiohttp \
    asyncio \
    python-nmap \
    colorama \
    termcolor \
    tqdm \
    pyyaml \
    jinja2 \
    click \
    tabulate \
    validators \
    dnspython \
    pycryptodome \
    urllib3 \
    certifi

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Python packages installed${NC}"
else
    echo -e "${YELLOW}[!] Some Python packages may have failed (non-critical)${NC}"
fi

##############################################
# PHASE 3: Go Tools Installation
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 3: Installing Go-based Tools${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Setup Go environment
echo -e "${BLUE}[*] Setting up Go environment...${NC}"
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Add to bashrc/zshrc if not already there
if ! grep -q "GOPATH" ~/.bashrc 2>/dev/null; then
    echo '' >> ~/.bashrc
    echo '# Go environment' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    echo -e "${GREEN}[✓] Go environment added to ~/.bashrc${NC}"
fi

if [ -f ~/.zshrc ]; then
    if ! grep -q "GOPATH" ~/.zshrc; then
        echo '' >> ~/.zshrc
        echo '# Go environment' >> ~/.zshrc
        echo 'export GOPATH=$HOME/go' >> ~/.zshrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
        echo -e "${GREEN}[✓] Go environment added to ~/.zshrc${NC}"
    fi
fi

# Install Subfinder
echo -e "${BLUE}[*] Installing Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | grep -v "go: downloading" || true
if command -v subfinder &> /dev/null || [ -f "$HOME/go/bin/subfinder" ]; then
    echo -e "${GREEN}[✓] Subfinder installed${NC}"
else
    echo -e "${RED}[!] Failed to install Subfinder${NC}"
fi

# Install httpx
echo -e "${BLUE}[*] Installing httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | grep -v "go: downloading" || true
if command -v httpx &> /dev/null || [ -f "$HOME/go/bin/httpx" ]; then
    echo -e "${GREEN}[✓] httpx installed${NC}"
else
    echo -e "${RED}[!] Failed to install httpx${NC}"
fi

# Install Nuclei
echo -e "${BLUE}[*] Installing Nuclei (this may take a while)...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | grep -v "go: downloading" || true
if command -v nuclei &> /dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
    echo -e "${GREEN}[✓] Nuclei installed${NC}"
    echo -e "${BLUE}[*] Updating Nuclei templates...${NC}"
    $HOME/go/bin/nuclei -update-templates -silent 2>&1 | tail -n 5
    echo -e "${GREEN}[✓] Nuclei templates updated${NC}"
else
    echo -e "${RED}[!] Failed to install Nuclei${NC}"
    echo -e "${YELLOW}[*] You can install it manually later with:${NC}"
    echo -e "${YELLOW}    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
fi

# Install ffuf
echo -e "${BLUE}[*] Installing ffuf...${NC}"
go install github.com/ffuf/ffuf/v2@latest 2>&1 | grep -v "go: downloading" || true
if command -v ffuf &> /dev/null || [ -f "$HOME/go/bin/ffuf" ]; then
    echo -e "${GREEN}[✓] ffuf installed${NC}"
else
    echo -e "${RED}[!] Failed to install ffuf${NC}"
fi

##############################################
# PHASE 4: Directory Structure Creation
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 4: Creating Directory Structure${NC}"
echo -e "${YELLOW}========================================${NC}\n"

echo -e "${BLUE}[*] Creating tool directories...${NC}"

# Create organized directory structure
mkdir -p "$INSTALL_DIR/tools/nmap"
mkdir -p "$INSTALL_DIR/tools/metasploit"
mkdir -p "$INSTALL_DIR/tools/sqlmap"
mkdir -p "$INSTALL_DIR/tools/nuclei"
mkdir -p "$INSTALL_DIR/tools/subfinder"
mkdir -p "$INSTALL_DIR/tools/httpx"
mkdir -p "$INSTALL_DIR/tools/ffuf"
mkdir -p "$INSTALL_DIR/wordlists"
mkdir -p "$INSTALL_DIR/Results"

echo -e "${GREEN}[✓] Directory structure created${NC}"

##############################################
# PHASE 5: Creating Tool Wrappers
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 5: Creating Tool Wrappers${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Create wrapper scripts for each tool
echo -e "${BLUE}[*] Creating Nmap wrapper...${NC}"
cat > "$INSTALL_DIR/tools/nmap/nmap" << 'NMAPEOF'
#!/bin/bash
/usr/bin/nmap "$@"
NMAPEOF
chmod +x "$INSTALL_DIR/tools/nmap/nmap"

echo -e "${BLUE}[*] Creating Metasploit wrapper...${NC}"
cat > "$INSTALL_DIR/tools/metasploit/msfconsole" << 'MSFEOF'
#!/bin/bash
/usr/bin/msfconsole "$@"
MSFEOF
chmod +x "$INSTALL_DIR/tools/metasploit/msfconsole"

echo -e "${BLUE}[*] Creating sqlmap wrapper...${NC}"
cat > "$INSTALL_DIR/tools/sqlmap/sqlmap" << 'SQLEOF'
#!/bin/bash
/usr/bin/sqlmap "$@"
SQLEOF
chmod +x "$INSTALL_DIR/tools/sqlmap/sqlmap"

echo -e "${BLUE}[*] Creating Nuclei wrapper...${NC}"
cat > "$INSTALL_DIR/tools/nuclei/nuclei" << 'NUCEOF'
#!/bin/bash
$HOME/go/bin/nuclei "$@"
NUCEOF
chmod +x "$INSTALL_DIR/tools/nuclei/nuclei"

echo -e "${BLUE}[*] Creating Subfinder wrapper...${NC}"
cat > "$INSTALL_DIR/tools/subfinder/subfinder" << 'SUBEOF'
#!/bin/bash
$HOME/go/bin/subfinder "$@"
SUBEOF
chmod +x "$INSTALL_DIR/tools/subfinder/subfinder"

echo -e "${BLUE}[*] Creating httpx wrapper...${NC}"
cat > "$INSTALL_DIR/tools/httpx/httpx" << 'HTTPEOF'
#!/bin/bash
$HOME/go/bin/httpx "$@"
HTTPEOF
chmod +x "$INSTALL_DIR/tools/httpx/httpx"

echo -e "${BLUE}[*] Creating ffuf wrapper...${NC}"
cat > "$INSTALL_DIR/tools/ffuf/ffuf" << 'FFUFEOF'
#!/bin/bash
$HOME/go/bin/ffuf "$@"
FFUFEOF
chmod +x "$INSTALL_DIR/tools/ffuf/ffuf"

echo -e "${GREEN}[✓] Tool wrappers created${NC}"

##############################################
# PHASE 6: Downloading Wordlists
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 6: Downloading Wordlists${NC}"
echo -e "${YELLOW}========================================${NC}\n"

echo -e "${BLUE}[*] Downloading SecLists (this may take a while)...${NC}"
if [ ! -d "$INSTALL_DIR/wordlists/SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$INSTALL_DIR/wordlists/SecLists" 2>&1 | grep -E "Cloning|Receiving|Resolving" || true
    if [ -d "$INSTALL_DIR/wordlists/SecLists" ]; then
        echo -e "${GREEN}[✓] SecLists downloaded${NC}"
    else
        echo -e "${YELLOW}[!] Failed to download SecLists (non-critical)${NC}"
        echo -e "${YELLOW}[*] You can download manually later:${NC}"
        echo -e "${YELLOW}    git clone https://github.com/danielmiessler/SecLists.git $INSTALL_DIR/wordlists/SecLists${NC}"
    fi
else
    echo -e "${GREEN}[✓] SecLists already exists${NC}"
fi

##############################################
# PHASE 7: Copy BountyRecon Script
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 7: Setting up BountyRecon${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Check if bountyrecon.py exists (try different possible names)
SCRIPT_DIR="$(dirname "$0")"
BOUNTY_SCRIPT=""

if [ -f "$SCRIPT_DIR/bountyrecon.py" ]; then
    BOUNTY_SCRIPT="$SCRIPT_DIR/bountyrecon.py"
elif [ -f "$SCRIPT_DIR/BountyRecon.py" ]; then
    BOUNTY_SCRIPT="$SCRIPT_DIR/BountyRecon.py"
elif [ -f "$SCRIPT_DIR/BountyRacon.py" ]; then
    BOUNTY_SCRIPT="$SCRIPT_DIR/BountyRacon.py"
fi

if [ -n "$BOUNTY_SCRIPT" ]; then
    echo -e "${BLUE}[*] Copying bountyrecon.py...${NC}"
    cp "$BOUNTY_SCRIPT" "$INSTALL_DIR/bountyrecon.py"
    chmod +x "$INSTALL_DIR/bountyrecon.py"
    echo -e "${GREEN}[✓] BountyRecon script installed${NC}"
elif [ -f "$INSTALL_DIR/bountyrecon.py" ]; then
    echo -e "${GREEN}[✓] BountyRecon script already exists${NC}"
else
    echo -e "${YELLOW}[!] bountyrecon.py not found${NC}"
    echo -e "${YELLOW}[*] Please manually copy bountyrecon.py to $INSTALL_DIR/${NC}"
fi

# Create initial list script
echo -e "${BLUE}[*] Creating Results list script...${NC}"
cat > "$INSTALL_DIR/Results/list" << 'LISTEOF'
#!/bin/bash

# BountyRecon Scan Results
echo -e '\033[1;36m═══════════════════════════════════════════════════════════\033[0m'
echo -e '\033[1;36m            BountyRecon - Scan Results\033[0m'
echo -e '\033[1;36m═══════════════════════════════════════════════════════════\033[0m\n'

# Count scans
scan_count=$(find . -maxdepth 1 -type d ! -name "." ! -name "Results" 2>/dev/null | wc -l)

if [ $scan_count -eq 0 ]; then
    echo -e '\033[1;33mNo scans found yet.\033[0m'
    echo -e '\033[1;32mRun a scan first: python3 ~/0xZan/bountyrecon.py -d example.com\033[0m\n'
else
    echo -e "\033[1;37mTotal scans: $scan_count\033[0m\n"
    
    # List all scan directories with numbers
    i=1
    for scan_dir in $(ls -dt */ 2>/dev/null | grep -v "^Results"); do
        scan_name=${scan_dir%/}
        echo -e "\033[1;33m[$i]\033[0m \033[1;37m$scan_name\033[0m"
        echo -e "    📂 cd $i"
        echo -e "    📄 cat $i/scan.txt"
        echo ""
        i=$((i+1))
    done
    
    echo -e '\033[1;32mUse: cd <number> to access a scan\033[0m'
    echo -e '\033[1;32mUse: cat <number>/scan.txt to view report\033[0m\n'
fi
LISTEOF

chmod +x "$INSTALL_DIR/Results/list"
echo -e "${GREEN}[✓] List script created${NC}"

##############################################
# PHASE 8: Verification
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 8: Installation Verification${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Function to check if command exists
check_tool() {
    if command -v $1 &> /dev/null || [ -f "$HOME/go/bin/$1" ]; then
        echo -e "${GREEN}[✓] $1 - Installed${NC}"
        return 0
    else
        echo -e "${RED}[✗] $1 - Not found${NC}"
        return 1
    fi
}

echo -e "${BLUE}[*] Verifying tool installations...${NC}\n"

check_tool nmap
check_tool sqlmap
check_tool msfconsole
check_tool subfinder
check_tool httpx
check_tool nuclei
check_tool ffuf
check_tool python3
check_tool pip3

##############################################
# PHASE 9: Final Setup
##############################################

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}PHASE 9: Final Configuration${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Create requirements.txt
echo -e "${BLUE}[*] Creating requirements.txt...${NC}"
cat > "$INSTALL_DIR/requirements.txt" << 'REQEOF'
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
aiohttp>=3.9.0
python-nmap>=0.7.1
colorama>=0.4.6
termcolor>=2.3.0
tqdm>=4.66.0
PyYAML>=6.0
Jinja2>=3.1.0
click>=8.1.0
tabulate>=0.9.0
validators>=0.22.0
dnspython>=2.4.0
pycryptodome>=3.19.0
urllib3>=2.1.0
certifi>=2023.11.0
REQEOF

echo -e "${GREEN}[✓] requirements.txt created${NC}"

##############################################
# Installation Complete
##############################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}     INSTALLATION COMPLETED!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${CYAN}Installation Summary:${NC}"
echo -e "  • System updated and dependencies installed"
echo -e "  • 7 security tools configured"
echo -e "  • Python environment ready"
echo -e "  • Directory structure created at: ${GREEN}$INSTALL_DIR${NC}"
echo -e "  • Wordlists downloaded"

echo -e "\n${CYAN}Directory Structure:${NC}"
echo -e "  $INSTALL_DIR/"
echo -e "  ├── bountyrecon.py      (Main scanner)"
echo -e "  ├── tools/              (All security tools)"
echo -e "  ├── Results/            (Scan results)"
echo -e "  └── wordlists/          (SecLists)"

echo -e "\n${YELLOW}Next Steps:${NC}"
echo -e "  1. ${GREEN}source ~/.bashrc${NC}  (or restart terminal)"
echo -e "  2. ${GREEN}cd ~/0xZan${NC}"
echo -e "  3. ${GREEN}python3 bountyrecon.py -h${NC}  (View help)"
echo -e "  4. ${GREEN}python3 bountyrecon.py -d example.com --quick${NC}  (Test run)"

echo -e "\n${CYAN}View Results:${NC}"
echo -e "  ${GREEN}cd ~/0xZan/Results && ./list${NC}"

echo -e "\n${BLUE}Installation log saved to: ${LOGFILE}${NC}"
echo -e "${BLUE}Happy Bug Hunting! 🎯${NC}\n"

# Offer to reload shell
echo -e "${YELLOW}[*] Shell restart recommended to apply PATH changes${NC}"
read -p "Open new terminal or source bashrc now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}[*] Run: source ~/.bashrc${NC}"
    echo -e "${GREEN}[*] Or close and reopen your terminal${NC}\n"
fi
