# WILAA 𓃠 ⋆˙⟡

Wilaa is an intelligent cybersecurity assistant designed to simplify and automate common vulnerability scanning tasks using an intuitive conversational interface. Powered by a Large Language Model (LLM), Wilaa interprets your requests and orchestrates popular security tools like Nmap, Nikto, and a custom Dirsearch implementation to perform network, web, and directory vulnerability assessments.

<img width="775" alt="Image" src="https://github.com/user-attachments/assets/cba9197c-c7fb-40ed-a46b-bb89a508f4b4" />

## Features ₊˚⊹

- **Conversational Interface**  
  Interact using natural language queries instead of complex CLI commands.

- **Intelligent Tool Selection**  
  Wilaa uses an LLM (via Ollama) to decide which tool is best suited for your query.

- **Automated Scan Execution**  
  Executes tools with the right parameters, abstracts away command-line complexity.

- **Comprehensive Scanning Capabilities**
  - **Network Scanning (Nmap)**: TCP, UDP, SYN scans, OS detection, service/version discovery.
  - **Web Vulnerability Scanning (Nikto)**: Detects misconfigurations, outdated software, and known issues.
  - **Directory Brute-Forcing (Dirsearch)**: Discovers hidden directories and files.

- **Structured Reporting**  
  Generates readable, deduplicated reports with scan summaries.

- **`sudo` Keep-Alive**  
  Maintains elevated privileges without repeated prompts.


## Installation ₊˚⊹

### Prerequisites ୨ৎ

Ensure the following tools are installed on your system:

- **Nmap**  
  Network scanning tool  
  - `sudo apt install nmap` (Ubuntu/Debian)  
  - `brew install nmap` (macOS)

- **Nikto**  
  Web vulnerability scanner  
  - `sudo apt install nikto`  
  - `brew install nikto`

- **Ollama**  
  Local LLM runtime  
  - [Download Ollama](https://ollama.ai/download)  
  - Then run:
    
    ```bash
    ollama run mistral
    ```
    *(This downloads the Mistral model. You can exit after it begins.)*


### Installation Steps ୨ৎ

1.  **Clone the repository (if applicable):**
   
    ```bash
    git clone https://github.com/Salozz/wilaa
    cd wilaa
    ```

3. Create a virtual environment (optional but recommended)

   ```bash
    python3 -m venv venv
    source venv/bin/activate
   ```

5.  **Run the setup script:**

    The `setup.sh` script will install all required Python packages and check for the presence of Nmap, Nikto, and Ollama.

    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```

    If any system dependencies are missing, the script will print an error message. Please install them manually as per the "Prerequisites" section.

6.  **Manual Installation (Alternative)**:

    If you prefer to install manually, first ensure all prerequisites are met, then install Python dependencies:
   
    ```bash
    pip install -r requirements.txt

    ```

## Usage ₊˚⊹

To start Wilaa, simply run the main Python script:

```bash
python3 wilaa.py
```


## License ₊˚⊹

MIT License — you're free to use, modify, and share this project.


## Contributions ₊˚⊹

Feel free to open issues or PRs to improve Wilaa. Let's make reconnaissance faster and smarter together. ♡ ₍^. .^⑅₎Ⳋ
