#!/bin/bash

##############################################
# 0xZan Directory Organization Script
# Created by: 0xZan
# Description: Organizes home directory with proper structure
##############################################

# Auto-fix line endings (in case of Windows upload issues)
sed -i 's/\r$//' "$0" 2>/dev/null

# Colors
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
                              
    Directory Organization
    Created by: 0xZan 
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] Organizing your 0xZan toolkit directory...${NC}\n"

# Main directory
OXZAN_DIR="$HOME/0xZan"

# Create main directory
echo -e "${BLUE}[*] Creating main directory: $OXZAN_DIR${NC}"
mkdir -p "$OXZAN_DIR"

# Create subdirectories
echo -e "${BLUE}[*] Creating subdirectories...${NC}"
mkdir -p "$OXZAN_DIR/tools/nmap"
mkdir -p "$OXZAN_DIR/tools/subfinder"
mkdir -p "$OXZAN_DIR/tools/httpx"
mkdir -p "$OXZAN_DIR/tools/nuclei"
mkdir -p "$OXZAN_DIR/tools/ffuf"
mkdir -p "$OXZAN_DIR/tools/sqlmap"
mkdir -p "$OXZAN_DIR/tools/metasploit"
mkdir -p "$OXZAN_DIR/Results"
mkdir -p "$OXZAN_DIR/wordlists"

echo -e "${GREEN}[✓] Directory structure created${NC}\n"

# Move existing tool directories if they exist in home
echo -e "${BLUE}[*] Moving existing tools to new structure...${NC}"

move_if_exists() {
    local tool_name=$1
    local old_dir="$HOME/$tool_name"
    local new_dir="$OXZAN_DIR/tools/$tool_name"
    
    if [ -d "$old_dir" ] && [ "$old_dir" != "$new_dir" ]; then
        echo -e "${YELLOW}  Moving $tool_name...${NC}"
        cp -r "$old_dir"/* "$new_dir/" 2>/dev/null || true
        echo -e "${GREEN}  ✓ $tool_name moved${NC}"
    fi
}

move_if_exists "nmap"
move_if_exists "subfinder"
move_if_exists "httpx"
move_if_exists "nuclei"
move_if_exists "ffuf"
move_if_exists "sqlmap"
move_if_exists "metasploit"

# Move wordlists if exists
if [ -d "$HOME/wordlists" ] && [ "$HOME/wordlists" != "$OXZAN_DIR/wordlists" ]; then
    echo -e "${YELLOW}  Moving wordlists...${NC}"
    cp -r "$HOME/wordlists"/* "$OXZAN_DIR/wordlists/" 2>/dev/null || true
    echo -e "${GREEN}  ✓ wordlists moved${NC}"
fi

# Move reports to Results if exists
if [ -d "$HOME/reports" ]; then
    echo -e "${YELLOW}  Moving old reports to Results...${NC}"
    cp -r "$HOME/reports"/* "$OXZAN_DIR/Results/" 2>/dev/null || true
    echo -e "${GREEN}  ✓ Reports moved${NC}"
fi

echo ""

# Create initial list script
echo -e "${BLUE}[*] Creating list script...${NC}"
cat > "$OXZAN_DIR/Results/list" << 'EOF'
#!/bin/bash

# BountyRecon Scan Results
# This script is auto-generated

echo -e '\033[1;36m═══════════════════════════════════════════════════════════\033[0m'
echo -e '\033[1;36m            BountyRecon - Scan Results\033[0m'
echo -e '\033[1;36m═══════════════════════════════════════════════════════════\033[0m\n'

# Count scans
scan_count=$(find . -maxdepth 1 -type d ! -name "." ! -name "Results" | wc -l)

if [ $scan_count -eq 0 ]; then
    echo -e '\033[1;33mNo scans found yet.\033[0m'
    echo -e '\033[1;32mRun a scan first: python3 ~/0xZan/bountyrecon.py -d example.com\033[0m\n'
else
    echo -e "\033[1;37mTotal scans: $scan_count\033[0m\n"
    echo -e '\033[1;33mUse: cd <number> to access a scan\033[0m'
    echo -e '\033[1;33mUse: cat <number>/scan.txt to view report\033[0m\n'
fi
EOF

chmod +x "$OXZAN_DIR/Results/list"
echo -e "${GREEN}[✓] List script created${NC}\n"

# Move bountyrecon.py if it exists in home
if [ -f "$HOME/bountyrecon.py" ]; then
    echo -e "${BLUE}[*] Moving bountyrecon.py to main directory...${NC}"
    cp "$HOME/bountyrecon.py" "$OXZAN_DIR/bountyrecon.py"
    echo -e "${GREEN}[✓] bountyrecon.py moved${NC}\n"
fi

# Show final structure
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}         ORGANIZATION COMPLETE!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

echo -e "${CYAN}Your new directory structure:${NC}\n"
echo -e "  ${YELLOW}~/0xZan/${NC}"
echo -e "  ├── ${CYAN}bountyrecon.py${NC}      (Main scanner)"
echo -e "  ├── ${CYAN}tools/${NC}              (All security tools)"
echo -e "  │   ├── nmap/"
echo -e "  │   ├── subfinder/"
echo -e "  │   ├── httpx/"
echo -e "  │   ├── nuclei/"
echo -e "  │   ├── ffuf/"
echo -e "  │   ├── sqlmap/"
echo -e "  │   └── metasploit/"
echo -e "  ├── ${CYAN}Results/${NC}            (Scan results)"
echo -e "  │   └── list           (View all scans)"
echo -e "  └── ${CYAN}wordlists/${NC}          (SecLists, etc.)"
echo -e ""

echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. ${GREEN}cd ~/0xZan${NC}"
echo -e "  2. ${GREEN}python3 bountyrecon.py -h${NC}  (View help)"
echo -e "  3. ${GREEN}cd Results && ./list${NC}       (View scans)"
echo -e ""

echo -e "${BLUE}Happy hunting! 🎯${NC}\n"