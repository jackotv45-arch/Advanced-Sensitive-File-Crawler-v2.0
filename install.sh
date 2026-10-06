#!/bin/bash

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Advanced Sensitive File Crawler - Installation          ║"
echo "╚══════════════════════════════════════════════════════════╝"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo -e "${RED}Error: Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python version OK: $PYTHON_VERSION${NC}"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 not found. Please install pip.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ pip3 found${NC}"

# Create virtual environment
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv $VENV_DIR
fi

echo -e "${GREEN}✓ Virtual environment ready${NC}"

# Activate virtual environment
source $VENV_DIR/bin/activate

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install requirements
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Install Playwright browsers
echo -e "${YELLOW}Installing Playwright browsers...${NC}"
playwright install chromium

# Make crawler executable
chmod +x crawler.py

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Installation Complete!                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usage:"
echo "  source $VENV_DIR/bin/activate"
echo "  python crawler.py https://target.com"
echo ""
echo "Options:"
echo "  python crawler.py --help"
echo ""

# Test import
echo -e "${YELLOW}Testing installation...${NC}"
python3 -c "import aiohttp; import playwright; print('All imports OK')" && echo -e "${GREEN}✓ All dependencies installed successfully${NC}" || echo -e "${RED}✗ Import error${NC}"
