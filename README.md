# WebRecon-Arsenal: A Comprehensive Web Application Reconnaissance Framework

CypherNova1337 presents **WebRecon-Arsenal**, a comprehensive framework for web application reconnaissance. This framework is built upon the foundational work of several respected security researchers, combined with my own techniques and workflow developed over time. It's designed to be a practical, adaptable, and educational resource for penetration testers and bug bounty hunters.

## Acknowledgements and Inspiration

This framework draws inspiration from the methodologies and tools used by many skilled individuals in the infosec community. While it's impossible to list everyone, I'd like to acknowledge the general influence of:

*   The broader bug bounty hunting community and their shared knowledge.
*   Public writeups and presentations on reconnaissance techniques.
*   Developers of the excellent open-source tools used in this framework.
*   @Coffinxp

This is a synthesis of best practices, not a copy of any single person's approach.

## Why Reconnaissance is *Everything*

Many aspiring web application pentesters are drawn to the field by the prospect of quick bug bounty rewards.  They often fall into the trap of immediately attempting exploits or running automated vulnerability scanners without a thorough understanding of the target application. This approach rarely leads to significant findings and often results in wasted effort.

**Reconnaissance is not just a preliminary step; it *is* the foundation upon which a successful penetration test is built.** A meticulous recon phase can be the deciding factor between identifying critical vulnerabilities and finding nothing of value. It's about building a comprehensive understanding of the target, including:

*   **Attack Surface:**  The totality of exposed assets.
*   **Technology Stack:**  Identifying the web server, framework, database, etc.
*   **Functionality:**  Grasping how the application operates, features, user roles, and data flows.
*   **Hidden Assets:**  Uncovering forgotten subdomains, dev environments, and exposed configuration files.

**The Time Commitment:**

Reconnaissance is not a quick process, *especially* for medium to large web applications.  The recon phase can easily span *weeks*, or even *months*. This is an investment.  The deeper your understanding of the target, the more effectively you can tailor your attacks.  The attack phase itself can also be a lengthy process, potentially taking weeks or months. There are thousands of recon methods.

## My Reconnaissance Methodology

This guide presents a multi-stage reconnaissance process that blends automated tools and manual analysis.  It's thorough, but adaptable. Tailor it to your specific targets.

**Key Principles:**

*   **Iterative:**  As you uncover new information, feed it back into your tools.
*   **Layered:**  Use multiple tools and techniques.
*   **Manual Analysis:**  Don't rely solely on automation.

**The Process (Step-by-Step):**

1.  **Preparation (One-Time Setup):**

    *   Install the required tools (see the install.md for detailed instructions).
    *   Create or obtain the necessary wordlists:
        *   `permutation_wordlist.txt`: For subdomain permutations (common prefixes, suffixes, numbers).  *Example: dev, test, staging, backup, 1, 2023, etc.*
             Good one to start with is: 
             ```bash
             https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4
             ```
        *   `vhost_wordlist.txt`: For virtual host discovery (common hostnames, your discovered subdomains). *Example: www, mail, dev, admin, etc.*
            Good one to start with is:
            ```bash
            https://github.com/maverickNerd/wordlists/blob/master/vhost.txt
            ```
        *   `parameter_fuzzing_wordlist.txt`: For fuzzing parameters.  SecLists is a good source:
            ```bash
            git clone https://github.com/danielmiessler/SecLists.git
            ```
        *   `xss_wordlist.txt`: For XSS payloads (SecLists).
            SecLists/Fuzzing/XSS/robot-friendly
        *   `resolvers.txt`: A list of known-good DNS resolvers.
            ```bash
            git clone https://github.com/trickest/resolvers.git
            ```
        *   `/home/USER/Documents/oneListForall/onelistforallshort.txt`: Your general-purpose directory brute-forcing wordlist. *Ensure this path is correct.*
            ```bash
            git clone https://github.com/six2dez/OneListForAll/blob/main/onelistforallshort.txt
            ```
        *  `/home/USER/Documents/nuclei-templates/`: Your Nuclei templates directory. *Ensure this path is correct.*

2.  **Reconnaissance Steps:**

    *   **Create Target Directory and `domains.txt`:**
        ```bash
        mkdir "TARGET"
        cd "TARGET" 
        nano domains.txt
        ```
        *Inside `nano`*: Enter in-scope domains, *one per line*, without `http://`, `https://`, `www`, or trailing slashes. Save (Ctrl+O, Enter) and exit (Ctrl+X).

    *   **Phase 1: Expanded Subdomain Enumeration**

        1.  **Subfinder (Initial Scan):**
            ```bash
            subfinder -dL domains.txt -all -recursive -o subdomains.txt
            ```
            *   **What:** Finds subdomains using passive sources. `-dL` reads domains from `domains.txt`. `-all` uses all sources. `-recursive` finds subdomains of subdomains. `-o` saves to `subdomains.txt`.
            *   **Why:** Expands the attack surface by identifying initial subdomains.

        2.  **crt.sh (Certificate Transparency):**
            ```bash
            curl -s "[https://crt.sh/?q=%25.$TARGET&output=json](https://crt.sh/?q=%25.$TARGET&output=json)" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew subdomains.txt
            ```
            *   **What:** Queries crt.sh for subdomains. `curl` fetches data, `jq` extracts domain names, `sed` removes wildcards, `anew` appends to `subdomains.txt` (no duplicates).
            *   **Why:** Finds subdomains from certificate transparency logs, often revealing hidden ones.

        3.  **Permutation Scanning (dnsgen + puredns + httpx):**
            ```bash
            cat subdomains.txt | dnsgen -w /path/to/your/permutation_wordlist.txt | puredns resolve -r /path/to/your/resolvers.txt -w permuted_subdomains.txt --wildcard-tests 5 --wildcard-threshold 0.8
            cat subdomains.txt permuted_subdomains.txt | anew subdomains.txt
            ```
            *   **What:** `dnsgen` creates subdomain variations. `puredns` resolves them (checks for valid IPs) using your `resolvers.txt` list. `--wildcard-tests` and `--wildcard-threshold` filter false positives. Finally, the results are combined.
            *   **Why:** Finds hidden subdomains with predictable naming patterns.

    *   **Phase 2: Subdomain Probing and Filtering**

        4.  **httpx (Live Host Discovery):**
            ```bash
            cat subdomains.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 -o subdomains_alive.txt -title -tech-detect
            ```
            *   **What:** Checks which subdomains have active web servers. `-ports` specifies common HTTP/HTTPS ports. `-threads` sets concurrency. `-o` saves live subdomains. `-title` and `-tech-detect` gather extra info.
            *   **Why:** Focuses on live targets and provides initial reconnaissance data.

    *   **Phase 3: URL Discovery and Content Extraction**

        5.  **Katana (Crawling):**
            ```bash
            katana -u subdomains_alive.txt -d 5 -c 50 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg >> allurls.txt
            ```
            *   **What:** Crawls websites to discover links and resources. `-u` sets starting URLs, `-d` is crawl depth, `-kf`, `-jc`,`-fx`, and `-ef` specify file extractions.
            *   **Why:** Maps the website's structure and content.

        6.  **GAU (Alternative URL Discovery):**
            ```bash
            cat subdomains_alive.txt | gau | anew allurls.txt
            ```
            * **What:** Gathers URLs from AlienVault OTX, Wayback Machine, and Common Crawl.
            * **Why:** Increases URL coverage from diverse sources.

        7.  **Waybackurls:**
             ```bash
             cat subdomains_alive.txt | waybackurls >> allurls.txt
              ```
            * **What:** Another tool using Wayback Machine
            *  **Why**: Gets more Urls

        8.  **Filter for Potentially Sensitive Files:**
            ```bash
            cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config" >> sens1.txt
            ```
            *   **What:** Filters URLs based on extensions associated with sensitive data.
            *   **Why:** Prioritizes URLs likely to contain sensitive information.

        9.  **Extract JavaScript Files:**
            ```bash
            cat allurls.txt | grep -E "\.js.?" | sort -u >> alljs.txt
            ```
            *   **What:** Isolates URLs pointing to JavaScript files.
            *   **Why:** JS files often contain valuable information for attackers.

        10. **Extract URLs from JavaScript (subjs):**
            ```bash
            cat alljs.txt | subjs >> js_extracted_urls.txt
            cat allurls.txt js_extracted_urls.txt | anew allurls.txt
            ```
            *   **What:** Parses JS code to extract embedded URLs.
            *   **Why:** Finds URLs loaded dynamically by JS, often missed by crawlers.
        11. **Unique Parameter Filtering**
            ```bash
            cat allurls.txt | uro -o filerparams.txt
            ```
           * **What**: Extracts unique parameters.
           *  **Why:** Identifies unique parameters for fuzzing.

    *   **Phase 4: Directory and File Brute-Forcing**

        12. **Dirsearch (General Wordlist):**
            ```bash
            dirsearch -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w /home/USER/Documents/oneListForall/onelistforallshort.txt
            ```
            *   **What:** Tries common directory/file names using a wordlist. `-l` targets live subdomains. `-x` excludes error codes. `-R` sets recursion depth. `--random-agent` helps avoid detection. `-t` is concurrency. `-F` follows redirects. `-w` specifies the wordlist.
            *   **Why:** Finds hidden content not linked from the website.
            *   **Note:** This step can take a *significant* amount of time, especially with a large wordlist like `onelistforallshort.txt` and a deep recursion level.  However, it can be run in the background while you proceed with other reconnaissance steps.  The `onelistforallshort.txt` wordlist is designed to be comprehensive, and using it with `dirsearch` can effectively map out the entire directory structure of the target application, potentially revealing a goldmine of hidden functionality and sensitive files – think of it as building your own detailed "blueprint" of the website.  This is why the output file is named `directory.txt`.

        13. **Dirsearch (Targeted Extensions - Iterative):**  Run this loop in your terminal.
            ```bash
            while read -r subdomain; do
              dirsearch -u "$subdomain" -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,eb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,[http://sql.zip](http://sql.zip),sql.tar.gz,sql~.swp.swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json -x 500,502,429,404,400 -R 2 --random-agent -t 20 -F -o "dirsearch_extensions_$subdomain.txt"
            done < subdomains_alive.txt
            ```
            *   **What:**  Runs `dirsearch` for *each* live subdomain, focusing on specific file extensions (`-e`).
            *   **Why:** Targets potentially sensitive file types (configs, backups, etc.).
            *   **Note:** This iterative approach, while also potentially time-consuming, can be run concurrently with other tasks.  It's a more focused attack than the general brute-force, increasing the chances of finding specific types of sensitive files on each subdomain.  Because it runs individually for each subdomain, the output is organized into separate files (`dirsearch_extensions_$subdomain.txt`), making analysis easier.
              
    *   **Phase 5: Vulnerability Scanning with Nuclei**

        14. **Nuclei (JS Exposures):**
            ```bash
            cat alljs.txt | nuclei -t /home/USER/Documents/nuclei-templates/http/exposures/ -c 30 -o nuclei_js_exposures.txt
            ```
            *   **What:** Scans JS files for common vulnerabilities using Nuclei templates.
            *   **Why:** Identifies potential security issues in JavaScript code.

        15. **Nuclei (General CVEs, OSINT, Tech):**
            ```bash
            nuclei -list subdomains_alive.txt -tags cves,osint,tech -o nuclei_general.txt
            ```
            *   **What:** Broad scan for known vulnerabilities, gathers OSINT data, and identifies technologies.
            *   **Why:** Identifies known exploits and technology details for targeted attacks.

        16. **Nuclei (CORS):**
            ```bash
            nuclei -list subdomains_alive.txt -t /home/USER/Documents/nuclei-templates/http/misconfiguration/cors/ -o nuclei_cors.txt
            ```
            *   **What:** Checks for Cross-Origin Resource Sharing (CORS) misconfigurations.
            *   **Why:** CORS issues can allow unauthorized data access.

        17. **Nuclei (CRLF):**
            ```bash
            nuclei -list subdomains_alive.txt -t /home/USER/Documents/nuclei-templates/http/crlf/ -o nuclei_crlf.txt
            ```
            *   **What:** Checks for CRLF injection vulnerabilities.
            *   **Why:** CRLF injection can lead to various attacks, including header manipulation.

        18. **Nuclei (LFI - using gf patterns):**
            ```bash
            cat allurls.txt | gf lfi | nuclei -tags lfi -o nuclei_lfi.txt
            ```
            *   **What:** Uses `gf` patterns to find potential Local File Inclusion (LFI) vulnerabilities, then scans them with Nuclei.
            *   **Why:** LFI allows attackers to read arbitrary files from the server.

    *   **Phase 6: Specialized Checks and Tools**

        19. **SecretFinder (JavaScript Secrets):** Run this loop in your terminal.
            ```bash
            cat alljs.txt | while read url; do python3 /path/to/SecretFinder/SecretFinder.py -i "$url" -o cli; done >> secret.txt
            ```
            *   **What:** Analyzes JS files for hardcoded secrets (API keys, passwords).
            *   **Why:** Finds potentially exposed credentials.

        20. **Subdomain Takeover (Subzy):**
            ```bash
            subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl >> subdomaintakeover.txt
            ```
            *   **What:** Checks if subdomains are vulnerable to takeover.
            *   **Why:** Prevents attackers from hijacking subdomains.

        21. **CORS Misconfiguration (Corsy):**
            ```bash
            python3 /path/to/Corsy/corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookies: SESSION=VoidSec" >> corsmisconf.txt
            ```
            *   **What:** Another check for CORS misconfigurations, using a different tool.
            *   **Why:** Provides a second opinion on CORS vulnerabilities.

        22. **Open Redirect (OpenRedirex):**
            ```bash
            cat allurls.txt | gf redirect | openredirex -o open_redirects.txt
            ```
            *   **What:** Identifies potential open redirect vulnerabilities using `gf` patterns.
            *   **Why:** Prevents attackers from redirecting users to malicious sites.

        23. **XSS (dalfox):** Replace `your_xss_endpoint_here` with your blind XSS collaborator URL.
            ```bash
            cat allurls.txt | dalfox -b your_xss_endpoint_here -o dalfox_xss.txt
            ```
            *   **What:**  Finds Cross-Site Scripting (XSS) vulnerabilities.
            *   **Why:** Prevents attackers from injecting malicious scripts.

    *   **Phase 7: Port Scan (naabu)**

        24. **Full Port Scan with Naabu + Nmap:**
            ```bash
            naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC -Pn' -o naabu-full.txt
            ```
            *   **What:** Performs a port scan and service version detection. `-nmap-cli` uses Nmap for detailed scanning. `-Pn` skips host discovery (important if ICMP is blocked).
            *   **Why:** Identifies open ports and running services, revealing potential attack vectors.

    *   **Phase 8: Virtual Host Discovery**

        25. **Extract IPs from naabu results:**
            ```bash
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' naabu-full.txt | sort -u > ips.txt
            ```
            * **What**: Gets the IP addresses
            *   **Why**: used for virtual host discovery

        26. **Vhost Discovery (ffuf):** Run this loop.
            ```bash
            while read -r ip; do
                ffuf -w subdomains.txt:FUZZ -u https://$ip -H "Host: FUZZ.$TARGET" -fs 0 -o vhost_results_"$ip".txt
            done < ips.txt
            ```
            *   **What:**  Tries different `Host` headers to find virtual hosts on the same IP. `-w` is the wordlist, `-u` is the URL, `-H` sets the `Host` header, `-fs 0` filters by response size (removes common responses).
            *   **Why:** Discovers hidden websites hosted on shared infrastructure.

    * **Phase 9: Parameter Fuzzing**

      
      27. **Parameter Fuzzing (XSS Example):**
            ```bash
            cat allurls.txt | gf xss | ffuf -w /path/to/your/xss_wordlist.txt:FUZZ -u FUZZ -fs 0 -o ffuf_xss_results.txt
            ```
            *   **What:**  Uses `gf` to find potential XSS parameters, then `ffuf` to fuzz those parameters with your `xss_wordlist.txt`.  `-fs 0` filters by response size.  This is an *example*; you can adapt this for other vulnerability types (SQLi, LFI, etc.) with different `gf` patterns and wordlists.
            *   **Why:**  Actively tests how the application handles potentially malicious input in parameters, looking for vulnerabilities.

    * **Phase 10: Screenshotting (aquatone)**

        28. **Take screenshots of live subdomains:**
            ```bash
            cat subdomains_alive.txt | aquatone -out aquatone_screenshots
            ```
            * **What:** Aquatone takes screenshots of websites.
            * **Why:** Visual inspection can reveal interesting features, login panels, or outdated software versions that might not be apparent from automated scans.

    * **Phase 11: sort.py**
      
        29. **Run custom sorting script:**
            ```bash
            python3 sort.py
            ```
      *   **What:** Sorts and filters the parameters.
      *   **Why:** makes output easier to look through.

## About `sort.py`

Included in this repository is a Python script, `sort.py`, designed to process the output of parameter discovery. This script performs the following actions:

1.  **Reads:** It reads a file named `filterparam.txt`. This file should contain a list of parameters, one per line (typically generated by tools like `uro`).
2.  **Sorts:** It sorts the parameters alphabetically.
3.  **Limits (Optional):** If the number of parameters is very large, it truncates the list to the first 100,000 entries. This is a practical consideration.
4.  **Writes:** It writes the sorted (and potentially truncated) list to a new file named `sorted_params_100000.txt`.
5.  **Credit:** Credit to @Coffinxp 

**Why this is useful:**

*   **Organization:** Sorting parameters helps in identifying patterns and prioritizing testing efforts.
*   **Performance:**  Some tools may perform better with a smaller, more focused set of parameters. You can always use the original `filterparam.txt` if needed.

**Manual Recon (Shodan):**

*   **Shodan Recon (Manual):** Perform these steps manually in the Shodan web interface.
    *   Search: `ssl:'target.com' 200`
    *   Click "More" on top organizations.
    *   Check `http.titles`
    *   Check `http.components`

    * **What:** Shodan is a search engine for internet-connected devices.
    * **Why:** Finds publicly exposed services, technologies, and potential vulnerabilities associated with the target's IP addresses.

## Conclusion

This reconnaissance process provides a strong foundation for web application penetration testing.  However, remember this is *my* generalized approach and might need adjustments for specific targets.  For larger organizations, consider researching business acquisitions and performing recon on those acquired companies' assets. There are countless other recon methods and steps; I adapt my approach based on the target. The key is to be adaptable, creative, and persistent.  This is a starting point; constant learning and adaptation are essential in the ever-evolving world of cybersecurity.

## Legal Disclaimer

This guide and the tools are for educational purposes and authorized testing *only*. Unauthorized hacking is illegal and unethical. Always obtain explicit, written permission before testing any system. I am not responsible for any misuse of this information.

---
