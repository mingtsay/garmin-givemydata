#!/usr/bin/env bash
# garmin-givemydata setup — one script to get everything running
set -e

echo
echo "  ╔══════════════════════════════════════╗"
echo "  ║       garmin-givemydata setup        ║"
echo "  ║    It's YOUR data. Take it back.     ║"
echo "  ╚══════════════════════════════════════╝"
echo

# ── Step 1: Check Python ──────────────────────────────────────
echo "[1/4] Checking Python..."

PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$cmd"
            echo "       Found Python $version ($cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo
    echo "  ERROR: Python 3.10+ is required but not found."
    echo
    echo "  Install it first:"
    echo "    macOS:   brew install python@3.12"
    echo "    Ubuntu:  sudo apt install python3.12 python3.12-venv"
    echo "    Fedora:  sudo dnf install python3.12"
    echo
    exit 1
fi

# ── Step 2: Create venv + install deps ────────────────────────
echo "[2/4] Setting up Python environment..."

if [ ! -d "venv" ]; then
    "$PYTHON" -m venv venv
fi
source venv/bin/activate

pip install --upgrade pip -q 2>&1 | tail -1
pip install -r requirements.txt -q 2>&1 | tail -1
echo "       Dependencies installed"

# ── Step 3: Verify TLS engine ─────────────────────────────────
echo "[3/4] Verifying TLS engine..."
if python -c "import curl_cffi" 2>/dev/null; then
    echo "       curl_cffi ready — no browser or chromedriver needed"
else
    echo "  WARNING: curl_cffi failed to import. Re-run after checking the pip output above."
fi

# ── Step 4: Garmin credentials ────────────────────────────────
echo "[4/4] Garmin Connect credentials"
echo

if [ -f ".env" ]; then
    echo "       .env file already exists."
    read -p "       Overwrite with new credentials? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "       Keeping existing credentials."
    else
        SETUP_CREDS=true
    fi
else
    SETUP_CREDS=true
fi

if [ "${SETUP_CREDS:-false}" = true ]; then
    echo "       Enter your Garmin Connect login credentials."
    echo "       (These are saved locally in .env and never sent anywhere)"
    echo
    read -p "       Email: " GARMIN_EMAIL
    read -s -p "       Password: " GARMIN_PASSWORD
    echo
    echo

    cat > .env << ENVEOF
GARMIN_EMAIL=${GARMIN_EMAIL}
GARMIN_PASSWORD=${GARMIN_PASSWORD}
ENVEOF
    chmod 600 .env
    echo "       Credentials saved to .env (permissions: owner-only)"
fi

# ── Done ──────────────────────────────────────────────────────
echo
echo "  ╔══════════════════════════════════════╗"
echo "  ║          Setup complete!             ║"
echo "  ╚══════════════════════════════════════╝"
echo
echo "  Fetch your data:"
echo
echo "    source venv/bin/activate"
echo "    python garmin_givemydata.py"
echo
echo "  If you have MFA enabled, enter the code when prompted."
echo
echo "  First run fetches all history (~30 min)."
echo "  After that, daily syncs take seconds."
echo
