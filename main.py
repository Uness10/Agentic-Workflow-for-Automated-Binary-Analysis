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

    # Initialize the agent
    # Note: Ensure you have OPENAI_API_KEY environment variable set
    agent = create_orchestrator()

    prompt = f"Perform a comprehensive security analysis on the binary file at: {binary_path}"
    
    print(f"--- Starting Analysis for {binary_path} ---\n")
    agent.print_response(prompt, stream=True)

if __name__ == "__main__":
    main()