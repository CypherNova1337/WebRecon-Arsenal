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
sudo apt install -y jq curl nmap dnsutils gobuster feroxbuster python3 python3-pip git
```
2. Install Go

This installs Go and sets up your GOPATH.
```bash

wget [https://golang.org/dl/go1.21.0.linux-amd64.tar.gz](https://golang.org/dl/go1.21.0.linux-amd64.tar.gz) # Check golang.org for the newest
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc
```
3. Install Go-Based Tools

These are installed with go install. Each command downloads, compiles, and installs a tool into $GOPATH/bin.
```bash

go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://www.google.com/search?q=https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder%40latest)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://www.google.com/search?q=https://github.com/projectdiscovery/httpx/cmd/httpx%40latest)
go install -v [github.com/projectdiscovery/naabu/v2/cmd/naabu@latest](https://www.google.com/search?q=https://github.com/projectdiscovery/naabu/v2/cmd/naabu%40latest)
go install -v [github.com/lc/subjs@latest](https://www.google.com/search?q=https://github.com/lc/subjs%40latest)
go install -v [github.com/tomnomnom/anew@latest](https://www.google.com/search?q=https://github.com/tomnomnom/anew%40latest)
go install -v [github.com/tomnomnom/gf@latest](https://www.google.com/search?q=https://github.com/tomnomnom/gf%40latest)
go install -v [github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest](https://www.google.com/search?q=https://github.com/dwisiswant0/crlfuzz/cmd/crlfuzz%40latest)
go install -v [github.com/devanshbatham/openredirex@latest](https://www.google.com/search?q=https://github.com/devanshbatham/openredirex%40latest)
go install [github.com/d3mondev/puredns/v2/cmd/puredns@latest](https://www.google.com/search?q=https://github.com/d3mondev/puredns/v2/cmd/puredns%40latest)
go install -v [github.com/hahwul/dalfox/v2@latest](https://www.google.com/search?q=https://github.com/hahwul/dalfox/v2%40latest)
go install -v [github.com/jaeles-project/gospider@latest](https://www.google.com/search?q=https://github.com/jaeles-project/gospider%40latest)
go install -v [github.com/LukaSikic/subzy@latest](https://www.google.com/search?q=https://github.com/LukaSikic/subzy%40latest)
go install -v [github.com/tomnomnom/waybackurls@latest](https://www.google.com/search?q=https://github.com/tomnomnom/waybackurls%40latest)
go install [github.com/tomnomnom/uro@latest](https://www.google.com/search?q=https://github.com/tomnomnom/uro%40latest)
go install -v [github.com/michenriksen/aquatone@latest](https://www.google.com/search?q=https://github.com/michenriksen/aquatone%40latest)
```
  subfinder: Fast subdomain enumeration.
  
  httpx: HTTP/HTTPS prober; checks for live web servers.
  
  naabu: Fast port scanner.
  
  subjs: Extracts URLs from JavaScript files.
  
  anew: Appends to a file, removing duplicates.
  
  gf: Provides patterns for grep.
  
  crlfuzz: CRLF injection fuzzer.
  
  openredirex: Open redirect fuzzer.
  
  puredns: Fast DNS resolver.
  
  dalfox: XSS scanner.
  
  gospider: Web spider.
  
  subzy: Subdomain takeover.
  
  waybackurls: Finds URLs from Wayback Machine.
  
  uro: Helps gather and filter URLs.
  
  aquatone: Takes website screenshots.
  

4. Install Python-Based Tools
```bash

pip3 install dnsgen requests beautifulsoup4 ffuf
```
  dnsgen: Generates subdomain permutations.
  requests: Makes HTTP requests (used by other tools).
  beautifulsoup4: HTML parser (used by other tools).
  ffuf: Web fuzzer.

5. Install Nuclei
```bash

wget [https://github.com/projectdiscovery/nuclei/releases/download/v3.1.9/nuclei_3.1.9_linux_amd64.zip](https://github.com/projectdiscovery/nuclei/releases/download/v3.1.9/nuclei_3.1.9_linux_amd64.zip) # Check for newest
unzip nuclei_3.1.9_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
nuclei -update-templates
```
  nuclei: Vulnerability Scanner

6. Install Corsy
```bash

git clone [https://github.com/s0md3v/Corsy.git](https://github.com/s0md3v/Corsy.git)
cd Corsy
pip3 install -r requirements.txt
```
  Corsy: Checks for CORS misconfigurations.

7. Install SecretFinder
```bash

git clone [https://github.com/m4ll0k/SecretFinder.git](https://github.com/m4ll0k/SecretFinder.git)
cd SecretFinder
pip3 install -r requirements.txt
```
  SecretFinder: Finds secrets in JavaScript files.

8. Tool-Specific Notes

    gau: Needs a config file (API keys). See: https://github.com/lc/gau
   
    puredns: Needs a resolvers.txt file (DNS servers).
   
    dalfox: For blind XSS, use a "collaborator" server.
   
    Nuclei: Update templates: nuclei -update-templates.
   

10. Organization (Recommended)

    Tools: /opt/tools, $HOME/tools, or /usr/local/bin (Go tools: $HOME/go/bin).
    
    Wordlists: A dedicated directory.
    
    Targets: A directory for each target.
    
