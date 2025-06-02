#!/bin/bash

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Checking system dependencies..."
which nmap >/dev/null || echo "[ERROR] Please install Nmap."
which nikto >/dev/null || echo "[ERROR]  Please install Nikto."
which ollama >/dev/null || echo "[ERROR]  Please install Ollama and load the 'mistral' model."

echo "Done. You're ready!"
