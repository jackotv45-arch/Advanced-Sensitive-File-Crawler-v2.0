#!/bin/bash

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Advanced Sensitive File Crawler v2.1                    ║"
echo "╚══════════════════════════════════════════════════════════╝"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ARCH=$(uname -m)
OS=$(uname -s)

echo -e "Architecture détectée: ${YELLOW}$ARCH${NC}"
echo -e "OS: ${YELLOW}$OS${NC}"

# Check Python
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo -e "${RED}Error: Python 3.8+ required${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}"

# Create venv
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv $VENV_DIR
fi

source $VENV_DIR/bin/activate
pip install --upgrade pip

# Install core requirements (sans Playwright d'abord)
echo -e "${YELLOW}Installing core dependencies...${NC}"
pip install aiohttp>=3.9.0 aiofiles rich questionary beautifulsoup4 lxml aiodns

# Try to install Playwright (peut échouer sur ARM)
echo -e "${YELLOW}Attempting Playwright installation...${NC}"
pip install playwright || echo -e "${YELLOW}⚠ Playwright pip install failed, will try alternative${NC}"

# Install browsers only if Playwright installed
if python3 -c "import playwright" 2>/dev/null; then
    echo -e "${YELLOW}Installing Playwright browsers...${NC}"
    
    # Détection architecture pour Playwright
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        echo -e "${YELLOW}Architecture ARM64 détectée - Installation spécifique...${NC}"
        # Sur ARM, il faut parfois installer Chromium manuellement
        playwright install chromium || {
            echo -e "${RED}⚠ Playwright browser install failed${NC}"
            echo -e "${YELLOW}Le crawler fonctionnera sans JavaScript rendering${NC}"
        }
    else
        playwright install chromium || {
            echo -e "${RED}⚠ Playwright browser install failed${NC}"
            echo -e "${YELLOW}Le crawler fonctionnera sans JavaScript rendering${NC}"
        }
    fi
else
    echo -e "${YELLOW}⚠ Playwright not available - JS rendering disabled${NC}"
fi

chmod +x crawler.py

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Installation Complete!                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usage:"
echo "  Interactive:  ./crawler.py --interactive"
echo "  CLI:          ./crawler.py https://target.com"
echo ""
if ! python3 -c "import playwright" 2>/dev/null; then
    echo -e "${YELLOW}Note: JavaScript rendering unavailable (install Playwright manually for JS support)${NC}"
fi
