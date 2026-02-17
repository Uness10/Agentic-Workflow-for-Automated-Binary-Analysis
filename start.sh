#!/bin/bash
set -e

echo "--- Initializing Analysis Agent ---"

# Check for LLM API Key (required by Agno)
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Warning: No LLM API Key found (OPENAI_API_KEY or ANTHROPIC_API_KEY)."
    echo "Agents will not function without a valid API key."
fi

# Validate Radare2 Installation
if ! command -v r2 &> /dev/null; then
    echo "Error: Radare2 (r2) is not installed."
    exit 1
fi

echo "Environment validation successful."

# Run the application or stay interactive
if [ "$1" == "shell" ]; then
    exec bash
else
    # Replace with the actual entry point of the application
    # For now, it just prints status as there's no main script yet
    echo "Ready for analysis. Running in interactive mode."
    exec bash
fi
