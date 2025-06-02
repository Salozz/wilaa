import os
import requests
import argparse
from datetime import datetime
import urllib.parse

# URL to a publicly available wordlist
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

# Function to download the wordlist
def download_wordlist():
    try:
        #print("\n[*] Downloading wordlist...")
        response = requests.get(WORDLIST_URL)
        response.raise_for_status()
        wordlist = response.text.splitlines()
        #print("\n[+] Wordlist downloaded successfully.")
        return wordlist
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Error downloading wordlist: {e}")
        return None

# Function to normalize the target URL or IP
def normalize_target(target):
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    if target.endswith("/"):
        target = target[:-1]
    return target

# Function to construct the URL based on the directory format
def construct_url(target_url, directory):
    if directory.startswith((".", "/", "_")):
        return f"{target_url}{directory}"
    return f"{target_url}/{directory}"

# Function to perform directory scanning
def scan_directory(target_url, wordlist):
    found_directories = []
    for directory in wordlist:
        url = construct_url(target_url, directory)
        try:
            response = requests.get(url)
            if response.status_code == 200:
                #print(f"[+] Found: {url}")
                found_directories.append(url)
            #else:
                #print(f"[-] Not Found: {url}")
        except requests.exceptions.RequestException:
            #print(f"[!] Error: {e}")
            continue
    return found_directories

# Function to generate a report of found directories
def generate_report(target_url, found_directories):
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.netloc or parsed.path
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    report_filename = f"dirsearch_report_{timestamp}.txt"
    with open(report_filename, 'w') as report_file:
        report_file.write("DIRSEARCH SCAN REPORT\n")
        report_file.write("=" * 50 + "\n")
        report_file.write(f"Target: {host}\n")
        report_file.write("=" * 50 + "\n")
        #report_file.write("## BEGIN DIRSEARCH ##\n\n")
        report_file.write(f"Total Directories Found: {len(found_directories)}\n\n")
        if not found_directories:
            report_file.write("No directories found. Report not generated.")
        
        for url in found_directories:
            path = url.replace(target_url, "") or "/"
            report_file.write(f"{path}\n")
        #report_file.write("\n## END DIRSEARCH ##\n")
        report_file.write("=" * 50 + "\n")
    return report_filename

# Find the most recent dirsearch report
def find_latest_report(prefix="dirsearch_report_"):
    files = [f for f in os.listdir('.') if f.startswith(prefix) and f.endswith('.txt')]
    if not files:
        return None
    files.sort(reverse=True)
    return files[0]

# Main entry for CLI usage
def main():
    parser = argparse.ArgumentParser(description="Directory Scanner Tool")
    parser.add_argument("target", help="Target URL or IP address")
    args = parser.parse_args()
    target_url = normalize_target(args.target)
    wordlist = download_wordlist()
    if not wordlist:
        return
    found = scan_directory(target_url, wordlist)
    report = generate_report(target_url, found)
    
    '''
    if report:
        print(f"Report saved as {report}")
        try:
            with open(report, 'r', encoding='utf-8') as f_report: # Specify encoding
                print(f_report.read()) # <<< Print the report content
        except FileNotFoundError:
            print(f"[ERROR] Report file {report} not found after generation.")
    '''

# Adapter for chatbot integration
def run_dirsearch(target):
    target_url = normalize_target(target)
    wordlist = download_wordlist()
    if not wordlist:
        return {"report": None}
    #print(f"[*] Running Dirsearch on {target_url}")
    found = scan_directory(target_url, wordlist)
    report = generate_report(target_url, found)
    latest = find_latest_report()

    print(f"\n\nStructured Dirsearch report saved to {report}")

    return {
        'report': latest,
        'success': True,
        'target': target,
        'paths_found': len(found)
    }

if __name__ == "__main__":
    main()
