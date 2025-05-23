# WebRecon-Arsenal: Tool Installation Guide

This guide provides instructions for installing the tools used in the `WebRecon-Arsenal` reconnaissance framework. These instructions are primarily for **Debian/Ubuntu-based Linux distributions**. Adapt them as needed for other distributions (Fedora, Arch, CentOS) or macOS.

## Important Notes

* **Tool Variety:** This framework uses tools written in **Go**, **Python**, and shell scripts.
* **Multiple Uses:** Many tools have capabilities beyond what's used here. Explore their documentation!
* **Configuration:** Some tools (e.g., `gau`) require configuration files (API keys). Refer to each tool's documentation.
* **Organization:** Keep tools and wordlists in dedicated locations. Wordlist paths are not specified here (you'll obtain them separately).

## Installation Steps

Copy and paste each command block into your terminal.

### 1. Basic System Tools (Debian/Ubuntu)

These are essential utilities.

```bash
sudo apt update
sudo apt-get -y install jq curl nmap dnsutils gobuster python3 python3-pip git massdns
```
2. Install Go

This installs Go and sets up your GOPATH.
```bash
wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```
3. Install Go-Based Tools

These are installed with go install. Each command downloads, compiles, and installs a tool into $GOPATH/bin.
```bash

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/lc/subjs@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
```
  subfinder: Fast subdomain enumeration.
  
  httpx: HTTP/HTTPS prober; checks for live web servers.
  
  naabu: Fast port scanner.
  
  subjs: Extracts URLs from JavaScript files.
  
  anew: Appends to a file, removing duplicates.
  
  gf: Provides patterns for grep.
  
  crlfuzz: CRLF injection fuzzer.
  
  puredns: Fast DNS resolver.
  
  dalfox: XSS scanner.
  
  gospider: Web spider.
  
  subzy: Subdomain takeover.
  
  waybackurls: Finds URLs from Wayback Machine.
  
  

4. Install Python-Based Tools
```bash

pip3 install dnsgen requests beautifulsoup4 
```
  dnsgen: Generates subdomain permutations.
  requests: Makes HTTP requests (used by other tools).
  beautifulsoup4: HTML parser (used by other tools).

5. Install Nuclei
```bash

wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.9/nuclei_3.1.9_linux_amd64.zip # Check for newest
unzip nuclei_3.1.9_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
nuclei -update-templates
```
  nuclei: Vulnerability Scanner

6. Install Corsy
```bash

git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install -r requirements.txt
```
  Corsy: Checks for CORS misconfigurations.

7. Install SecretFinder
```bash

git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder
pip3 install -r requirements.txt
```
  SecretFinder: Finds secrets in JavaScript files.

7. Install OpenRedirex
   ```bash
   git clone https://github.com/devanshbatham/openredirex
   cd openredirex
   sudo chmod +x setup.sh
   ./setup.sh
   ```
8. Install Uro
   ```bash
   pipx install uro
   ```
   NOTE: if using older version of python, pip will work for installing as well.
   
9. Tool-Specific Notes

    gau: Needs a config file (API keys). See: https://github.com/lc/gau
   
    puredns: Needs a resolvers.txt file (DNS servers).
   
    dalfox: For blind XSS, use a "collaborator" server.
   
    Nuclei: Update templates: nuclei -update-templates.
   

10. Organization (Recommended)

    Tools: /opt/tools, $HOME/tools, or /usr/local/bin (Go tools: $HOME/go/bin).
    
    Wordlists: A dedicated directory.
    
    Targets: A directory for each target.
    
