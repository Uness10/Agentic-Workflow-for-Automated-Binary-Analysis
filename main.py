import sys
import os
from agents.orchestrator import create_orchestrator


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_binary>")
        sys.exit(1)

    binary_path = sys.argv[1]

    # Ensure the file exists
    if not os.path.exists(binary_path):
        print(f"Error: File '{binary_path}' not found.")
        sys.exit(1)

    # Debug flag: set DEBUG=1 to see tool calls
    debug = os.getenv("DEBUG", "0") == "1"

    # Initialize the agent
    agent = create_orchestrator()

    if debug:
        agent.show_tool_calls = True

    prompt = (
        f"Perform a comprehensive security analysis on the binary file at: {binary_path}\n"
        f"Use each of your tools (extract_metadata, detect_crypto, analyze_strings, "
        f"analyze_syscalls, detect_obfuscation) and report findings based ONLY on "
        f"the real tool outputs."
    )

    print(f"--- Starting Analysis for {binary_path} ---\n")
    agent.print_response(prompt, stream=True)


if __name__ == "__main__":
    main()