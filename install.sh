#!/bin/bash

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Advanced Sensitive File Crawler v2.1                    ║"
echo "║  With Interactive Menu                                   ║"
echo "╚══════════════════════════════════════════════════════════╝"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Install requirements
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

# Install Playwright
echo -e "${YELLOW}Installing Playwright browsers...${NC}"
playwright install chromium

# Make executable
chmod +x crawler.py

# Create symlink for easy access
if [ ! -f "/usr/local/bin/sensitive-crawler" ] && [ "$EUID" -eq 0 ]; then
    ln -sf "$(pwd)/crawler.py" /usr/local/bin/sensitive-crawler
    echo -e "${GREEN}✓ Created system command: sensitive-crawler${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Installation Complete!                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usage modes:"
echo "  Interactive:  python crawler.py --interactive"
echo "  CLI:          python crawler.py https://target.com"
echo ""
echo "Quick start:"
echo "  source $VENV_DIR/bin/activate"
echo "  python crawler.py -i"
echo ""

# Test
python3 -c "import rich, questionary, aiohttp, playwright; print('✓ All dependencies OK')"
