#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_DIR="venv"
if [ ! -d "$ENV_DIR" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$ENV_DIR"
fi

echo "Activating virtual environment..."
. "$ENV_DIR/bin/activate"

echo "Upgrading pip..."
pip install --upgrade pip

if [ -f requirements.txt ]; then
  echo "Installing dependencies..."
  pip install -r requirements.txt
else
  echo "Error: requirements.txt not found"
  exit 1
fi

echo "Starting application..."
python main.py
