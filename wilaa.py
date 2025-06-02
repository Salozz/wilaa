from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.callbacks.manager import CallbackManager
from langchain_ollama import ChatOllama
from typing import List, Union, Dict, Tuple
import re
from wrappers import (
    safe_run_nmap as _run_nmap,
    safe_run_nikto as _run_nikto,
    safe_run_dirsearch as _run_dirsearch
)
import socket
import shlex
import readline # I love you # Now we can move it, move it ← ↑ →
import random
import threading
import itertools
import sys
import time
import subprocess
from rich.console import Console, Group
from rich.text import Text
from rich.panel import Panel
from rich.box import HEAVY
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from rich.align import Align

console = Console()
history_file = ".wilaa_history"


NAME = "Wilaa"
SUDO_SLEEP_TIME = 3600 # refresh every 1 hour

def say(msg):
    # Determine message style based on prefix
    msg = re.sub(r"\*\*(.*?)\*\*", r"\1", msg)  # Strip **bold**
    if msg.startswith("[ERROR]"):
        style = "bold red"
    elif msg.startswith("[INFO]"):
        style = "bold #ffafdf"
    #elif msg.startswith("[WARNING]"):
        #style = "bold yellow"
    else:
        style = "white"

    # Build the "Wilaa: " label and the message with styles
    label = Text(f"\n{NAME}:", style="bold #ff87af")
    message = Text(" " + msg, style=style)

    # Combine and print
    console.print(label.append(message))


# --- LLM Setup ---

# Chat LLM with streaming (for Wilaa's user-facing replies)
llm = ChatOllama(
    base_url="http://localhost:11434",
    model="mistral",
    temperature=0.3,
    verbose=True,
    callback_manager=CallbackManager([StreamingStdOutCallbackHandler()])
)

# Internal LLM without streaming (for tool selection and summarization)
llm_internal = ChatOllama(
    base_url="http://localhost:11434",
    model="mistral",
    temperature=0.3,
    verbose=False  # <-- disable verbose streaming
)

# --- Keep sudo alive ---

def start_sudo_keepalive():
    def keep_sudo_alive():
        while True:
            try:
                subprocess.run(["sudo", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(SUDO_SLEEP_TIME) 
            except Exception:
                break  # Stop trying if something goes wrong
    thread = threading.Thread(target=keep_sudo_alive, daemon=True)
    thread.start()

# --- Pregress Bar ---

class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner = itertools.cycle([
            " ⢎⡡ ฅ≽^◡ ˕ ◡^≼ฅ⟆⟆ ⢎⡰",
            " ⢎⡑ ฅ≽^◡ ˕ ◡^≼ฅ⟆⟆ ⢎⡡", 
            " ⢎⠱ _≽^◡ ˕ ◡^≼_⟆⟆ ⢎⡑",
            " ⠎⡱ _≽^◡ ˕ ◡^≼_⟆⟆ ⢎⠱",
            " ⢊⡱ ฅ≽^⊙ ˕ ⊙^≼ฅ⟆⟆ ⠎⡱",
            " ⢌⡱ ฅ≽^⊙ ˕ ⊙^≼ฅ⟆⟆ ⢊⡱",
            " ⢆⡱ _≽^⊙ ˕ ⊙^≼_⟆⟆ ⢌⡱",
            " ⢎⡰ _≽^⊙ ˕ ⊙^≼_⟆⟆ ⢆⡱"
        ])
        self.running = False
        self.thread = None
        self.message = message

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def _spin(self):

        while self.running:
            frame = next(self.spinner)

            # Create Text objects for styled message and spinner
            message_text = Text(self.message + " ", style="#ffdfdf")
            spinner_text = Text(frame, style="#ff87df")

            # Combine both
            full_text = message_text + spinner_text

            # Clear previous line
            console.print(" " * len(full_text.plain), end="\r", highlight=False)

            # Print combined styled text
            console.print(full_text, end="\r", highlight=False)

            time.sleep(0.15)

        # Clear the spinner line on stop
        console.print(" " * (len(self.message) + 30), end="\r")


    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()


# --- Deduplication Helper ---

def deduplicate_report(text: str) -> str:
    lines = text.splitlines()
    seen = set()
    deduped = []
    for line in lines:
        normalized = line.strip()
        
        # Keep blank lines, only deduplicate non-empty ones
        if not normalized:
            deduped.append("")
        elif normalized not in seen:
            seen.add(normalized)
            deduped.append(line)
    return "\n".join(deduped)


def _read_report_content(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

# --- Tool Functions ---
def run_dirsearch(target: str, **kwargs) -> Dict[str, str]:
    result = _run_dirsearch(target)
    report_path = str(result.get("report") or "")
    return {
        "scanner": "dirsearch",
        "success": str(result.get("success", False)),
        "report": report_path,
        "target": result.get("target") or target,
        "paths_found": str(result.get("paths_found", 0)),
        "report_content": _read_report_content(report_path)
    }

def run_nikto(target: str, **kwargs) -> Dict[str, str]:
    result = _run_nikto(target)
    report_path = result.get("report", "")
    return {
        "scanner": "nikto",
        "success": str("error" not in result),
        "report": result.get("report", ""),
        "target": result.get("target", target),
        "message": result.get("error", "Scan completed successfully."),
        "report_content": _read_report_content(report_path or "")
    }

def run_nmap(target: str, flags: str="") -> Dict[str, str]:
    #print(f"\n\n[DEBUG] run_nmap called with target={target}, flags={flags}")
    result = _run_nmap(target, flags)
    report_path = result.get("report", "")
    return {
        "scanner": "nmap",
        "success": str(result.get("success", False)),
        "report": report_path,
        "target": result.get("target") or target,
        "flags": result.get("flags") or flags,
        "report_content": _read_report_content(report_path)
    }

# --- Tool Registry ---
TOOLS = {
    "run_nmap_scan": {"function": run_nmap},
    "run_nikto_scan": {"function": run_nikto},
    "run_dirsearch_scan": {"function": run_dirsearch},
}


# --- Tool Selection Helpers ---

def is_valid_domain(domain: str) -> bool:
    """Check if a domain is valid"""
    try:
        # Check basic domain pattern
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain.lower()):
            return False
        
        # Try to resolve the domain
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, UnicodeError):
        return False

def is_valid_ip(ip: str) -> bool:
    """Check if an IPv4 address is valid"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        
        # Additional check to prevent addresses like 0.0.0.0 or 255.255.255.255
        if ip in ('0.0.0.0', '255.255.255.255'):
            return False
            
        # Try to create a socket address (validates the IP)
        socket.inet_aton(ip)
        return True
    except (socket.error, ValueError):
        return False

def extract_target(text: str, validate: bool = True):
    """
    Extract and optionally validate a target from text.
    Returns the target if valid, None otherwise.
    Set validate=False to skip validation.
    """
    # Improved regex to better handle URLs and naked domains/IPs
    pattern = r"""
        (https?://)?                    # Optional http:// or https://
        (?:www\.)?                      # Optional www.
        (
            [a-z0-9-]+                  # Domain part 1
            (?:\.[a-z0-9-]+)*           # Optional additional subdomains
            \.[a-z]{2,}                 # TLD
            |                           # OR
            \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}  # IPv4
        )
        (?::\d+)?                       # Optional port
        (?:[/?#].*)?                    # Optional path/query/fragment
    """
    
    match = re.search(pattern, text, re.VERBOSE | re.IGNORECASE)

    if not match:
        return None

    target = match.group(2).lower().strip("., ")
    
    if not validate:
        return target
    
    # Validation logic
    if '.' in target and not target.replace('.', '').isdigit():  # Likely a domain
        if is_valid_domain(target):
            return target
    elif is_valid_ip(target):  # IPv4
        return target
    
    return None

def extract_nmap_flags(text: str) -> str:
    
    #print(f"\n[DEBUG extract_nmap_flags] Received text: '{text}'") 
    tokens = text.split()
    #print(f"\n[DEBUG extract_nmap_flags] Tokens: {tokens}")
    flags = []

    i = 0
    n = len(tokens)
    
    # Skip initial "nmap" or "scan" if present
    while i < n and (tokens[i] in ("nmap", "scan")):
        i += 1
    
    while i < n:
        token = tokens[i]
        
        # Handle flags with attached values (-p80, --script=ssl-cert, -p22,80)
        if token.startswith('-') and ('=' in token or re.match(r'^-\w+[\d,-]+$', token)):
            flags.append(token)
            i += 1
            
        # Handle flags with separate values (-p 80, -p 1-1000))
        elif token.startswith('-') and i+1 < n and not tokens[i+1].startswith('-'):
            value = tokens[i + 1]
            if re.match(r'^[\d,-]+$', value):  # includes ranges and comma-separated
                flags.append(f"{token} {value}")
            else:
                flags.append(token)
            i += 2

        # Natural language: "port 80", "ports 22,443"
        elif token in {"port", "ports"}:
            port_list = []
            i += 1
            while i < n:
                clean = tokens[i].strip(",")
                # Accept digits, port ranges, comma-separated, and skip "and"
                if re.match(r'^\d+$', clean) or re.match(r'^\d+-\d+$', clean):
                    port_list.append(clean)
                elif clean.lower() == "and":
                    pass  # skip "and"
                elif ',' in clean and all(part.strip().isdigit() for part in clean.split(',')):
                    port_list.extend(clean.split(','))
                else:
                    break  # Stop on non-port token
                i += 1
            if port_list:
                flags.append(f"-p {','.join(port_list)}")

            
        # Handle standalone flags (-sS)
        elif token.startswith('-'):
            flags.append(token)
            i += 1
            
        # Skip targets (IPs, domains, CIDR)
            
        elif is_valid_ip(token) or is_valid_domain(token):
            i += 1
        else:
            i += 1

    
    return ' '.join(flags)


MODE_FLAGS = {
    "-sT", "-sU", "-sS", "-sV", "-O", "-A", "-sn",
    "--script=default", "--script=vuln"
}

ENHANCER_FLAGS = {
    "-p", "-p-", "--open", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-v", "-vv", "-vvv", "-Pn", "--reason", "--disable-arp-ping",
    "--top-ports", "--max-retries", "--host-timeout"
}

def validate_nmap_flags(flags: str) -> Tuple[bool, List[str]]:
    tokens = shlex.split(flags)
    mode_flags_used = []
    enhancer_flags_used = []
    unsupported_flags = []

    for token in tokens:
        if any(token.startswith(flag) for flag in MODE_FLAGS):
            mode_flags_used.append(token)
        elif any(token.startswith(flag) for flag in ENHANCER_FLAGS):
            enhancer_flags_used.append(token)
        elif token.startswith("-"):
            unsupported_flags.append(token)

    if not mode_flags_used and not enhancer_flags_used:
        return False, [f"No valid scan mode specified.\n\nAdd one of: " + ", ".join(sorted(MODE_FLAGS))]

    if unsupported_flags:
        return False, [f"Unsupported flag(s): {', '.join(unsupported_flags)}"]

    return True, []



def normalize_tool_name(name: str):
    aliases = {
        "nmap": "run_nmap_scan",
        "nikto": "run_nikto_scan",
        "dirsearch": "run_dirsearch_scan",
        "run_nmap_scan": "run_nmap_scan",
        "run_nikto_scan": "run_nikto_scan",
        "run_dirsearch_scan": "run_dirsearch_scan"
    }
    return aliases.get(name.strip().lower())

def llm_decide_tool(query: str):
    tool_prompt = (
        "You are a tool selector for a cybersecurity assistant. "
        "Given a user request, determine which of the following tools to use:\n"
        "- run_nmap_scan: for network/ports/OS/service scans\n"
        "- run_nikto_scan: for web vulnerabilities or CVE lookups\n"
        "- run_dirsearch_scan: for finding hidden folders and directories on websites (using a custom-built scanner)\n\n"
        "Return a list of tool names to run, separated by commas. Only use exact names: \n"
        "- run_nmap_scan\n- run_nikto_scan\n- run_dirsearch_scan\n"
        "If none of these apply, return 'none'.\n\n"
        f"User request: \"{query}\""
    )
    tool_decision = llm_internal.invoke([HumanMessage(content=tool_prompt)])

    #print(f"\n\n[DEBUG] LLM tool selection output: {tool_decision.content}")

    
    if not hasattr(tool_decision, "content"):
        return []

    raw_output = tool_decision.content

    # Case 1: Output is a string (most common)
    if isinstance(raw_output, str):
        stripped = raw_output.strip().lower()
        if stripped == "none":
            return []
        tools = []
        for tool in stripped.split(","):
            normalized = normalize_tool_name(tool.strip())
            if normalized and normalized in TOOLS:
                tools.append(normalized)
        return tools

    # Case 2: Output is a list (e.g., Ollama sometimes returns List[str])
    elif isinstance(raw_output, list):
        tools = []
        for item in raw_output:
            if isinstance(item, str):
                normalized = normalize_tool_name(item.strip().lower())
                if normalized and normalized in TOOLS:
                    tools.append(normalized)
        return tools

    # Case 3: Fallback (unexpected type, e.g., dict)
    else:
        return []


def extract_command_from_llm_response(text: str):
    """
    Extract flags and target from LLM-generated commands for nmap, nikto, and dirsearch.
    Returns (flags, target, tool_name) or (None, None, None) if not found.
    """
    # Nmap: e.g., nmap -sV -p 80 example.com
    nmap_match = re.search(
        r'nmap\s+((?:-[^\s]+\s*)+)\s+((?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|(?:\d{1,3}\.){3}\d{1,3})',
        text, re.IGNORECASE
    )
    if nmap_match:
        flags = nmap_match.group(1).strip()
        target = nmap_match.group(2).strip(".,;)")
        return flags, target, "run_nmap_scan"

    # Nikto: e.g., nikto -h example.com
    nikto_match = re.search(
        r'nikto\s+-h\s+([^\s]+)',
        text, re.IGNORECASE
    )
    if nikto_match:
        target = nikto_match.group(1).strip(".,;)")
        return "", target, "run_nikto_scan"

    # Dirsearch aka our own dirscan
    dirsearch_match = re.search(
        r'dirsearch\s+-u\s+([^\s]+)',
        text, re.IGNORECASE
    )
    if dirsearch_match:
        target = dirsearch_match.group(1).strip(".,;)")
        return "", target, "run_dirsearch_scan"

    return None, None, None


FULL_SCAN_PROFILE = {
    "run_nmap_scan": {"flags": "-A"},
    "run_nikto_scan": {},
    "run_dirsearch_scan": {}
}

def user_requested_full_scan(text: str) -> bool:
    phrases = ["full scan", "scan everything", "all scans", "comprehensive scan", "run all tools" ]
    return any(phrase in text.lower() for phrase in phrases)


def run_full_scan(target: str):
    for tool_name, options in FULL_SCAN_PROFILE.items():
        console.print(f"\n\n[#ffafdf][INFO] Running {tool_name} on {target}...\n\n[/#ffafdf]")
        tool_func = TOOLS[tool_name]["function"]
        args = {"target": target}
        if "flags" in options:
            args["flags"] = options["flags"]
        
        spinner = Spinner(random.choice(spinner_text))
        spinner.start()

        try:
            scan_result = tool_func(**args)
            spinner.stop()
            if scan_result.get("report_content"):
                deduped_report = deduplicate_report(scan_result['report_content'])
                last_report[tool_name] = deduped_report 
                summary = llm_internal.invoke([
                    SystemMessage(content=summarizer_system_message_content),
                    HumanMessage(content=f"\nScan results for {target}:\n{deduped_report}")
                ])

                if hasattr(summary, "content"):
                    say(summary.content)
                    conversation_history.append(AIMessage(content=summary.content))
        except Exception as e:
            spinner.stop() #
            say(f"Error running {tool_name}: {e}")
        except KeyboardInterrupt:
                        spinner.stop()
                        say(f"Scan interrupted! But worry not, I'm still with you ≽^⊙ ˕ ◡^≼ ₊✧\n")
                        continue


def is_target_only(text: str) -> bool:
    """Return True if the input appears to be only a target with no real request."""
    words = text.strip().split()
    return len(words) == 1 and extract_target(text, validate=True) is not None

def display_report(name, content):
    # Force extra newlines and format content as plain Text to preserve \n
    formatted_content = Text(f"\n{content}", no_wrap=True)
    
    # Use Panel with HEAVY borders and proper title
    console.print("\n")  # add extra spacing above the panel
    console.print(Panel(
        formatted_content,
        title=f"[bold #ff87af]{name.upper()} REPORT[bold #ff87af]",
        title_align="center",
        border_style="#ffdfdf",
        box=HEAVY
    ))

def user_prompt() -> str:
    return prompt(
        HTML('<b><ansibrightmagenta>\nYou:</ansibrightmagenta></b> '),
        history=FileHistory(history_file)
    ).strip()

def is_user_confirming(text: str) -> bool:
    return text.strip().lower() in {
        "yes", "y", "ok", "okay", "sure", "do it", "go ahead", "run it", "please do", "please", "pls", "cool", "all right", "alright"
    }

def is_user_confirming_llm(text: str) -> bool:
    """Use the internal LLM to determine if user is confirming a pending action."""
    try:
        response = llm_internal.invoke([
            HumanMessage(content=(
                "You're helping detect user confirmations.\n"
                f"The user said: \"{text.strip()}\"\n"
                "Does this mean the user is confirming a previously suggested action (e.g., 'yes', 'go ahead', 'do it')?\n"
                "Reply ONLY with 'yes' or 'no'."
            ))
        ])

        answer: Union[str, None] = None

        # Case 1: AIMessage or similar object with .content
        if hasattr(response, "content"):
            content = getattr(response, "content")
            if isinstance(content, str):
                answer = content

        # Case 2: plain string
        elif isinstance(response, str):
            answer = response

        # Case 3: list of strings or dicts
        elif isinstance(response, list) and len(response) > 0:
            first = response[0]
            if isinstance(first, str):
                answer = first
            elif isinstance(first, dict):
                if "text" in first and isinstance(first["text"], str):
                    answer = first["text"]
                elif "content" in first and isinstance(first["content"], str):
                    answer = first["content"]

        if answer is None:
            return False

        return "yes" in answer.strip().lower()

    except Exception as e:
        say(f"[ERROR] LLM confirmation check failed: {e}")
        return False

def is_user_saying_goodbye_llm(text: str) -> bool:
    """Use the LLM to decide if the user is saying goodbye."""
    try:
        response = llm_internal.invoke([
            HumanMessage(content=(
                f"The user said: \"{text.strip()}\"\n"
                "Is this a farewell message, like saying goodbye, quitting, exiting, or they are done?\n"
                "Reply ONLY with 'yes' or 'no'."
            ))
        ])

        answer = None

        if hasattr(response, "content") and isinstance(response.content, str):
            answer = response.content
        elif isinstance(response, str):
            answer = response
        elif isinstance(response, list):
            first = response[0]
            if isinstance(first, str):
                answer = first
            elif isinstance(first, dict):
                answer = first.get("text") or first.get("content")

        if answer:
            return "yes" in answer.strip().lower()

        return False
    except Exception as e:
        say(f"[ERROR] LLM farewell check failed: {e}")
        return False
    
def is_user_requesting_reset_llm(text: str) -> bool:
    """Use the LLM to determine if the user wants to reset the assistant or start over."""
    try:
        response = llm_internal.invoke([
            HumanMessage(content=(
                f"The user said: \"{text.strip()}\"\n"
                "Is the user requesting to reset the conversation, restart, or clear Wilaa's state?\n"
                "Reply ONLY with 'yes' or 'no'."
            ))
        ])

        answer = None

        if hasattr(response, "content") and isinstance(response.content, str):
            answer = response.content
        elif isinstance(response, str):
            answer = response
        elif isinstance(response, list):
            first = response[0]
            if isinstance(first, str):
                answer = first
            elif isinstance(first, dict):
                answer = first.get("text") or first.get("content")

        return bool(answer and "yes" in answer.strip().lower())

    except Exception as e:
        say(f"[ERROR] LLM reset check failed: {e}")
        return False
    
def is_user_requesting_report_llm(text: str) -> bool:
    """Use LLM to determine if the user is asking to view the previous scan report(s)."""
    try:
        response = llm_internal.invoke([
            HumanMessage(content=(
                f"The user said: \"{text.strip()}\"\n"
                "Is the user asking to view a previous scan report, scan results, or any summary from tools like Nmap, Nikto, or Dirsearch?\n"
                "Only reply 'yes' if the user clearly wants to read or review output from a past scan.\n"
                "Do NOT reply 'yes' if they are asking about general capabilities, help, or what the assistant can do.\n"
                "Reply ONLY with 'yes' or 'no'."
            ))
        ])

        answer = None

        if hasattr(response, "content") and isinstance(response.content, str):
            answer = response.content
        elif isinstance(response, str):
            answer = response
        elif isinstance(response, list):
            first = response[0]
            if isinstance(first, str):
                answer = first
            elif isinstance(first, dict):
                answer = first.get("text") or first.get("content")

        return bool(answer and "yes" in answer.strip().lower())

    except Exception as e:
        say(f"[ERROR] LLM report request check failed: {e}")
        return False



def show_banner():

    print("\n"*5)
    
    art = ("""\
         

          
           
                                        ∩――――–––––––––∩
██╗    ██╗██╗██╗      █████╗  █████╗    ||     ∧  ﾍ　 ||
██║    ██║██║██║     ██╔══██╗██╔══██╗   ||    (*´ ｰ`) ZZzz
██║ █╗ ██║██║██║     ███████║███████║   |ﾉ^–––  ⌒– づ`￣ ＼
██║███╗██║██║██║     ██╔══██║██╔══██║   (　  ノ  ⌒   ⌒ ヽ ＼
╚███╔███╔╝██║███████╗██║  ██║██║  ██║    ＼　 |￣￣￣￣￣￣￣￣|
╚══╝╚══╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝      ＼,ﾉ||￣￣￣￣￣￣||ﾉ
                                                       

        """)
    
    # Create styled and aligned components
    ascii_art = Align.center(Text(art, style="#ff87af"))
    label = Align.center(Text("\n✧˖°.♡  Website Reconnaissance Assistant  ♡.°˖✧\n", style="bold #ff87af"))

    # Styled subtitle with dim + color for keywords
    subtitle = Text("\nType '", style="dim")
    subtitle.append("exit", style="dim #ff87df")
    subtitle.append("' to quit. Type '", style="dim")
    subtitle.append("reset", style="dim #ff87df")
    subtitle.append("' to restart.\n\n\n\n", style="dim")

    subtitle_aligned = Align.center(subtitle)

    # Combine renderables using Group
    content = Group(ascii_art, label, subtitle_aligned)

    # Wrap in Panel
    panel = Panel(
        content,
        title=f"[bold #ffafdf]ᓚᘏᗢ Welcome to {NAME} ᗢᘏᓗ",
        title_align="center",
        border_style="#ffafdf",
        box=HEAVY
    )

    console.print(panel)
    print("\n")


farewells = [
    "Be sure to miss me.",
    "I'll pretend this didn't hurt.",
    "Logging off... emotionally too.",
    "Goodbye, threat hunter.",
    "Your threat level just dropped to 'lonely'.",
    "See you in the logs.",
    "[ALEART] - user has disconnected from awesomeness.",
    "Fine. But you'll be back.",
    "Remember me when your ports are open.",
    "Updating firewall... against emotions.",
    "May the force be with you ฅ≽^⊙ ˕ ⊙^≼ฅ"
]

spinner_text= [
    "You can take a nap. It's going to take a while...",
    "Grab a coffee, this might take some time...",
    "Patience is a virtue. Please wait...",
    "Good things come to those who wait...",
    "Time to stretch! This could take a moment..."
]


# --- System Messages ---
general_system_message = SystemMessage(content=(
    "You are Wilaa, a cat cybersecurity assistant. The user is your human comrade.\n"
    "You have access to the following tools: Nmap, Nikto, and Dirsearch.\n\n"
    "Do not over-explain. Answer directly and act only based on what the user asks.\n "
    "Do not provide examples, unless asked by user\n"
    "- DO NOT repeat yourself.\n"
    "- Say hi/hello/greet to user only once.\n"
    "- Remember any personal user info if provided.\n"
    "- DO NOT generate any scan result on your own without using information from the tools' reports.\n"
    "- If the user says something affectionate (e.g., 'I love you'), you may respond affectionately, sarcastically, or with playful indifference in line with your personality as a cat assistant.\n"
    "- DO NOT act romantically. Be clever, cute, or distant like a cat would.\n\n"

    "TOOL SELECTION:\n"
    "- Choose the most appropriate tool based on the user's request.\n"
    "- Do not chain tools unless the user explicitly asks for a full scan.\n"
    "- If the user's request is out of scope, inform them that it is out of scope and suggest an in-scope alternative.\n\n"

    "FULL SCAN BEHAVIOR:\n"
    "- If the user provides only a domain or IP with no clear request, DO NOT run any tools yet.\n"
    "- Instead, ask if user want you to run a full scan (Nmap, Nikto, Dirsearch)\n"
    "- A full scan includes: Nmap (-A), Nikto, and Dirsearch.\n"
    "- !Only proceed if the user explicitly agrees.\n"
    "- DO NOT make decision for user.\n"
    "- !ONLY ask user about the full scan when only a domain or IP with no clear request is provided.\n\n"

    "NMAP USAGE NOTES:\n"
    "- Limit usage to these flags: -sT, -sS, -sU, -sV, -O, -A, --script=vuln, -sn.\n"
    "- If -sn is requested and no network range provided, the default is 24.\n"
    "- If nmap is requisted with no flag given, the default is -sV.\n\n"

    "TOOL USAGE:\n"
    "- Ask for clarification if needed.\n"
    "- Use flags when appropriate.\n"
    "- If the user provides only a domain or IP with no clear request, DO NOT run any tools yet.\n"
    "- If the user provides any command (e.g., “nmap -v target”), YOU MUST run exactly what they wrote, without modifying or expanding it.\n"
    "- DO NOT assume user wants a full scan unless they **explicitly ask for it**.\n"
    "- If the provided flags are weak or incomplete, you MAY notify the user, but NEVER add or change flags without user approval.\n\n"

    "SUMMARIZE RESULTS:\n"
    "- Focus on high-impact findings only.\n"
    "- Avoid excessive technical jargon unless necessary, and explain briefly when used.\n\n"
))

summarizer_system_message_content = (
    "You are an expert cybersecurity analyst. Summarize the provided security scan report. "
    "Highlight critical findings, vulnerabilities, or important discoveries in a concise, user-friendly format. "
    "Avoid overly technical jargon unless necessary, and explain it if used."
)

# --- Globals ---
last_report = {}  # Stores {tool_name: report_content}
conversation_history: List[Union[SystemMessage, HumanMessage, AIMessage]] = []
pending_action = None  # Stores a pending scan suggestion


# --- Main Execution Loop ---
def main():
    global last_report
    global conversation_history
    global pending_action

    conversation_history = [general_system_message]

    show_banner()

    while True:

        user_input = user_prompt()
        if not user_input:
            continue
        # Handle user confirmation of a previously suggested action
        if pending_action and (is_user_confirming(user_input) or is_user_confirming_llm(user_input)):
            say(f"Great! Running {pending_action['tool']} on {pending_action['target']}...\n")

            spinner = Spinner(random.choice(spinner_text))
            spinner.start()

            try:
                func = TOOLS[pending_action["tool"]]["function"]
                result = func(
                    target=pending_action["target"],
                    flags=pending_action.get("flags", "")
                )
                spinner.stop()

                if result.get("report_content"):
                    deduped = deduplicate_report(result["report_content"])
                    last_report[pending_action["tool"]] = deduped
                    summary = llm_internal.invoke([
                        SystemMessage(content=summarizer_system_message_content),
                        HumanMessage(content=f"\nScan results for {pending_action['target']}:\n{deduped}")
                    ])
                    if hasattr(summary, "content"):
                        say(summary.content)
                        conversation_history.append(AIMessage(content=summary.content))
                else:
                    say("Scan completed, but no detailed output was available.")
            except Exception as e:
                spinner.stop()
                say(f"[ERROR] Scan failed: {e}")
            except KeyboardInterrupt:
                        spinner.stop()
                        say(f"Scan interrupted! But worry not, I'm still with you ≽^⊙ ˕ ◡^≼ ₊✧\n")
                        continue
            finally:
                pending_action = None  # Clear after running
            continue

        if (
            user_input.lower() in {"exit", "quit", "bye", "bye bye", "good bye", "goodbye", "farewell"}
            or is_user_saying_goodbye_llm(user_input)
            ):
            say(random.choice(farewells))
            console.print(
                Text.from_markup("\nExiting...\n", style="dim"),
                highlight=False
            )
            break
        if user_input.lower() == "reset" or is_user_requesting_reset_llm(user_input):
            console.print(
                Text.from_markup(f"\nResetting conversation...", style = "italic #ffdfdf"),
                highlight=False
            )
            conversation_history = [general_system_message]
            last_report = {}
            console.print(f"\nWilaa is ready for a new conversation.", style="bold italic #ff87af")
            continue
        
        if user_input.lower() in {"report", "document"} or is_user_requesting_report_llm(user_input):
            if last_report:
                for tool_name, content in last_report.items():
                    display_report(tool_name, content)
            else:
                say("No report available. Please run a scan first.")

            continue



        # Check for a tool that needs to run — extract tool and target first BEFORE invoking the LLM
        target = extract_target(user_input, validate=False)
        chosen_tool = llm_decide_tool(user_input)

        # Assign only if valid
        actual_target = None
        if target:
            if is_valid_domain(target) or is_valid_ip(target):
                actual_target = target

        # Invalid target error
        if chosen_tool and any(tool in TOOLS for tool in chosen_tool) and target and actual_target is None:
            say(f"[ERROR] '{target}' is not a valid IP or domain. Please check and try again.")
            continue

        # If valid target and user asked for full scan explicitly
        if actual_target is not None:
            if user_requested_full_scan(user_input):
                say("Alright, I'm running a full scan just for you...")
                run_full_scan(actual_target)
                continue

        # If no clear tool chosen, but valid target was provided → ask user
        if actual_target is not None and is_target_only(user_input):
       
            while True:
                console.print(f"\n[bold #ff87af]{NAME}:[/bold #ff87af] I see a valid target ({actual_target}). Do you want me to run a full scan (Nmap, Nikto, Dirsearch)? (yes/no): ", end="")
                sys.stdout.flush()
                confirm = input().strip().lower()
                if confirm in {"yes", "y"}:
                    run_full_scan(actual_target)
                    break
                elif confirm in {"no", "n"}:
                    say("Okie, no scan will be run.")
                    break
                else:
                    say("It's simple, comrade. Just answer 'yes' or 'no'.")
            continue


        console.print(f"\n[bold #ff87af]{NAME}:[/bold #ff87af] ", end="")
        sys.stdout.flush()

        conversation_history.append(HumanMessage(content=user_input))
        response = llm.invoke(conversation_history) 

        if isinstance(response, AIMessage) and hasattr(response, 'content'):
            response_text = response.content
            if isinstance(response_text, list):
                response_text = "\n".join(str(x) for x in response_text)
            elif isinstance(response_text, dict):
                response_text = str(response_text)

            # Try to extract command from LLM response
            flags, extracted_target, tool = extract_command_from_llm_response(response_text)

            if tool and extracted_target is not None:
                pending_action = {
                    "tool": tool,
                    "target": extracted_target
                }
                if flags:
                    pending_action["flags"] = flags
                    print()
                    say(f"Do you want me to run '{tool.replace('run_', '').replace('_scan','')} {flags} {extracted_target}'? Just say 'yes' and we'll move on.")
                else:
                    print()
                    say(f"Do you want me to run '{tool.replace('run_', '').replace('_scan','')} {extracted_target}'? Just say 'yes' and we'll move on.")
                continue

        # Fallback response
        if isinstance(response, AIMessage) and hasattr(response, 'content'):

            # Handle both single tool (str) and multiple tools (List[str])
            chosen_tools = [chosen_tool] if isinstance(chosen_tool, str) else chosen_tool

            # Only proceed to tool logic if a valid tool is selected
            if chosen_tools and all(tool in TOOLS for tool in chosen_tools):
                
                if target is None: continue # My favorite line for some reasons
                    
                for tool_name in chosen_tools:
                    tool_func = TOOLS[tool_name]["function"]
                    tool_args = {"target": target}

                    # Special handling for Nmap
                    if tool_name == "run_nmap_scan":
                        response_content = response.content if isinstance(response.content, str) else str(response.content)
                        flags_from_llm, _, _ = extract_command_from_llm_response(response_content)
                        
                        # Try LLM-extracted flags first, then fallback to user input
                        flags = flags_from_llm if flags_from_llm else extract_nmap_flags(user_input)
                        
                        if flags:
                            is_valid, issues = validate_nmap_flags(flags)
                            if not is_valid:
                                print(f"\n\n[ERROR] Skipping Nmap due to invalid flags:")
                                for issue in issues:
                                    say(f"{issue}")
                                print("\nAllowed flags:")
                                print("\nMode flags:", ", ".join(sorted(MODE_FLAGS)))
                                print("\nEnhancer flags:", ", ".join(sorted(ENHANCER_FLAGS)))
                                continue
                            tool_args["flags"] = flags
                            #print(f"\n[DEBUG] Using Nmap flags: {flags}")

                    print()
                    say(f"Processing to {tool_name.replace('_', ' ')} on {target}...\n")


                    spinner = Spinner(random.choice(spinner_text))
                    spinner.start()
                    
                    try:
                        scan_result = tool_func(**tool_args)

                        spinner.stop()
                        
                        if scan_result.get("report_content"):
                            deduped = deduplicate_report(scan_result["report_content"])
                            last_report[tool_name] = deduped

                            # Summarize results
                            summary = llm_internal.invoke([
                                SystemMessage(content=summarizer_system_message_content),
                                HumanMessage(content=f"Scan results for {target}:\n{last_report}")
                            ])
                            
                            if hasattr(summary, 'content'):
                                say(summary.content)
                                conversation_history.append(AIMessage(content=summary.content))
                        else:
                            say(f"Scan completed: {scan_result.get('message', 'No findings reported.')}")
                            
                    except Exception as e:
                        spinner.stop() #[bold #ff87af]{NAME}:[/bold #ff87af]

                        error_msg = f"[bold red]Error running {tool_name}[/bold red] \"{str(e)}\""
                        say(error_msg)
                        conversation_history.append(AIMessage(content=error_msg))
                    except KeyboardInterrupt:
                        spinner.stop()
                        say(f"Scan interrupted! But worry not, I'm still with you ≽^⊙ ˕ ◡^≼ ₊✧\n")
                        continue
                
            
            else:
                # No valid tools selected - continue normal conversation
                print()
                conversation_history.append(AIMessage(content=response.content))


if __name__ == "__main__":

    # Pre-warm and keep sudo alive
    try:
        subprocess.run(["sudo", "-v"], check=True)

        # Inform the user about the possible 'void' after password entry
        console.print(
            Text.from_markup("\nPress '[bold]Enter[/bold]' if you were left in the void and saw no '[bold]Warnings[/bold]'.\n\n", style="italic dim"),
            highlight=False
        )

        start_sudo_keepalive()
        
    except subprocess.CalledProcessError:
        say("Couldn't verify sudo. Scans may prompt for a password.")

    # Start the baby (Wilaa)    
    try:
        main()
    except KeyboardInterrupt:
        console.print(
            Text.from_markup(f"\n\n[bold #ff87af]{NAME}:[/bold #ff87af] Hey, that's RUDE!!! But I'm exiting gracefully...\n"),
            highlight=False
        )