# WebRecon-Arsenal: A Comprehensive Web Application Reconnaissance Framework

CypherNova1337 presents **WebRecon-Arsenal**, a comprehensive framework for web application reconnaissance. This framework is built upon the foundational work of several respected security researchers, combined with my own techniques, workflow and tools developed over time. It's designed to be a practical, adaptable, and educational resource for penetration testers and bug bounty hunters.

This guide is for programs where **subdomains are in scope** (`*.target.com`). It goes wide on purpose: subdomain enumeration, permutation, takeovers, virtual hosts. Out-of-scope hosts and keywords are stripped at every step with `scope_filter.py`, so the wide net never lands on something you aren't allowed to touch.

If only the apex domain is in scope (no subdomains at all), use [DomainDive](https://github.com/CypherNova1337/DomainDive) instead.

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

*   **Scope First:**  Write down what's out of scope before you run anything, and filter every result against it.
*   **Iterative:**  As you uncover new information, feed it back into your tools.
*   **Layered:**  Use multiple tools and techniques.
*   **Manual Analysis:**  Don't rely solely on automation.

**Fast Path: VoidRecon**

[VoidRecon](https://github.com/CypherNova1337/VoidRecon) is this whole pipeline as one engine: subdomains, resolving, probing, crawling and vuln checks, with scope enforced by the engine itself. Once `domains.txt` and `out_of_scope.txt` exist (step 2 below):

```bash
{ cat domains.txt; grep '\.' out_of_scope.txt | grep -v '/' | sed 's/^/!/'; } > voidrecon_scope.txt
voidrecon scope -S voidrecon_scope.txt                         # check the effective scope first
voidrecon run -S voidrecon_scope.txt -p quick                  # passive
voidrecon run -S voidrecon_scope.txt --active -p standard      # active
```

Lines starting with `!` are exclusions. VoidRecon scopes by host, so keyword and path exclusions (like `contact`) still need `scope_filter.py`. The manual process below goes deeper and gives you control over every request; I run both.

**The Process (Step-by-Step):**

1.  **Preparation (One-Time Setup):**

    *   Install the required tools (see the [install.md](install.md) for detailed instructions). Everything goes in `~/tools/`, which is the path used below.
    *   Create or obtain the necessary wordlists:
        *   **Subdomain permutations:** Built into [DNS-Helix](https://github.com/CypherNova1337/dns-helix), along with a vetted resolver list. Nothing to download. Pass `-w` / `-r` only if you want your own.
        *   `vhost_wordlist.txt`: For virtual host discovery (common hostnames, your discovered subdomains). *Example: www, mail, dev, admin, etc.*
            Good one to start with is:
            ```bash
            https://github.com/maverickNerd/wordlists/blob/master/vhost.txt
            ```
        *   **Parameter names:** Built into [paramvoid](https://github.com/CypherNova1337/paramvoid).
        *   `~/tools/wordlists/onelistforall.txt`: Your general-purpose directory brute-forcing wordlist, from [OneListForAll](https://github.com/six2dez/OneListForAll). The old `onelistforallshort.txt` was replaced; install.md covers getting the current list.
        *   `~/nuclei-templates/`: The community Nuclei templates (`nuclei -update-templates`), plus my [Personal_Nuclei_Templates](https://github.com/CypherNova1337/Personal_Nuclei_Templates) in `~/tools/`.

          I highly recommend using my [GF_Patterns](https://github.com/CypherNova1337/GF_Patterns), rewritten for the modern web (format-anchored secret patterns, LLM keys, modern frameworks). Copy them to your `~/.gf` folder (hidden folder):
           ```bash
           git clone https://github.com/CypherNova1337/GF_Patterns ~/tools/GF_Patterns
           mkdir -p ~/.gf && cp ~/tools/GF_Patterns/*.json ~/.gf/
           ```

2.  **Reconnaissance Steps:**

    *   **Create Target Directory, `domains.txt` and `out_of_scope.txt`:**
        ```bash
        mkdir "TARGET"
        cd "TARGET"
        nano domains.txt
        ```
        *Inside `nano`*: Enter in-scope domains, *one per line*, without `http://`, `https://`, `www`, or trailing slashes. A bare `target.com` covers all of its subdomains. Save (Ctrl+O, Enter) and exit (Ctrl+X).

        ```bash
        nano out_of_scope.txt
        ```
        *Inside `nano`*: Enter everything the program says is Out Of Scope, *one per line*:
        ```text
        sub.domain.com
        *.staging.domain.com
        contact
        /logout
        ```
        *   `sub.domain.com` removes that subdomain and everything under it.
        *   `*.staging.domain.com` removes everything under `staging.domain.com` (but not `staging.domain.com` itself).
        *   Anything without a dot, or with a `/`, is a keyword: any line containing it is removed. `contact` drops anything regarding contact forms.

        If nothing is out of scope, still create the file: `touch out_of_scope.txt`.

    *   **Load the Scope Filter:** Run this in the terminal you're working in. Every step below pipes its results through it.
        ```bash
        inscope() { python3 ~/tools/WebRecon-Arsenal/scope_filter.py -s domains.txt -x out_of_scope.txt "$@"; }
        ```
        *   **What:** Keeps only lines whose host is one of your domains or a subdomain of one, then removes anything matching `out_of_scope.txt`. It understands bare hosts, URLs, and tool output like httpx's.
        *   **Why:** This replaces the old one-off `grep -v` step. Because the out-of-scope list is applied everywhere, there's no separate `filtered_subdomains.txt` to remember to swap in — `subdomains.txt` is always the clean list.

    *   **Phase 1: Expanded Subdomain Enumeration**

        1.  **Subfinder (Initial Scan):**
            ```bash
            subfinder -dL domains.txt -all -recursive -o subdomains_raw.txt
            ```
            *   **What:** Finds subdomains using passive sources. `-dL` reads domains from `domains.txt`. `-all` uses all sources. `-recursive` finds subdomains of subdomains. `-o` saves to `subdomains_raw.txt`.
            *   **Why:** Expands the attack surface by identifying initial subdomains.

        2.  **crt.sh (Certificate Transparency):**
            ```bash
            while read -r domain; do
                for q in "" "&exclude=expired"; do
                    for try in 1 2 3; do
                        json=$(curl -s -m 120 "https://crt.sh/?q=%25.$domain&output=json$q")
                        echo "$json" | jq -e 'type == "array"' >/dev/null 2>&1 && break 2
                        sleep $((try * 10))
                    done
                done
                if echo "$json" | jq -e 'type == "array"' >/dev/null 2>&1; then
                    echo "$json" | jq -r '.[].name_value' | sed 's/^\*\.//' | tr 'A-Z' 'a-z' | sort -u | anew subdomains_raw.txt
                else
                    echo "crt.sh failed for $domain, skipping (subfinder already queries crt.sh)" >&2
                fi
                sleep 5
            done < domains.txt
            ```
            *   **What:** Queries crt.sh for subdomains of each domain. `curl` fetches data, `jq` extracts domain names, `sed` removes wildcards, `anew` appends to `subdomains_raw.txt` (no duplicates).
            *   **Why:** Finds subdomains from certificate transparency logs, often revealing hidden ones.
            *   **Note:** On big organizations crt.sh often can't finish the full-history query and returns an HTML `502 Bad Gateway` page instead of JSON. That page is what made jq throw `parse error: Invalid numeric literal`. The loop now checks that the response is real JSON before parsing it, retries three times with a growing wait, then falls back to `&exclude=expired` (live certificates only), which is much lighter and usually goes through. If both fail it says so and moves on to the next domain instead of printing jq errors.

        3.  **Remove Out-Of-Scope Subdomains:**
            ```bash
            inscope subdomains_raw.txt > subdomains.txt
            ```
            *   **What:** Drops everything in `out_of_scope.txt`, plus any unrelated domains the sources returned.
            *   **Why:** Everything after this reads `subdomains.txt`, so nothing out of scope gets permuted, probed or scanned.

        4.  **Permutation Scanning (DNS-Helix):**
            ```bash
            dns-helix -s subdomains.txt -pre-validate -o permuted_subdomains.txt
            inscope permuted_subdomains.txt | anew subdomains.txt
            ```
            *   **What:** [DNS-Helix](https://github.com/CypherNova1337/dns-helix) builds variations of the subdomains you already have (`api` → `api-dev`, `api2`, `api-staging`, `dev-api` ...) and resolves them at speed with its built-in resolver list. `-pre-validate` skips dead seeds so they don't generate thousands of useless names. The results go back through the scope filter — a permutation of an in-scope name can still land on an excluded one.
            *   **Why:** Finds hidden subdomains with predictable naming patterns that no public source lists.
            *   **Note:** This can take some time, but it is worth every second. It is also a high bandwidth scan (1000 queries per second by default), meaning it might cause issues with other devices like a gaming console on the same network. Ease off with `-t 25 -l 200`, or skip this step if disrupting other things on the network is a no go. You'll still have a good attack field, just might miss some stuff. Also don't combine this scan with other background scans like dirsearch. If it gets interrupted, add `-resume run.state` and run the same command again.

    *   **Phase 2: Subdomain Probing and Filtering**

        5.  **httpx (Live Host Discovery):**
            ```bash
            cat subdomains.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 -title -tech-detect -status-code -o Tech_Subdomains_alive.txt
            cat Tech_Subdomains_alive.txt | awk '{print $1}' | inscope | sort -u > subdomains_alive.txt
            ```
            *   **What:** Checks which subdomains have active web servers. `-ports` specifies common HTTP/HTTPS ports. `-threads` sets concurrency. `-o` saves live subdomains. `-title`, `-status-code` and `-tech-detect` gather extra info.
            *   **Why:** Focuses on live targets and provides initial reconnaissance data.

    *   **Phase 3: URL Discovery and Content Extraction**

        6.  **Katana (Crawling):**
            ```bash
            katana -list subdomains_alive.txt -d 5 -c 50 -kf all -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif | inscope | anew allurls.txt
            ```
            *   **What:** Crawls websites to discover links and resources. `-list` sets starting URLs, `-d` is crawl depth, `-kf`, `-jc`,`-fx`, and `-ef` specify file extractions.
            *   **Why:** Maps the website's structure and content.

        7.  **GAU (Alternative URL Discovery):**
            ```bash
            cat domains.txt | gau --subs | inscope | anew allurls.txt
            ```
            * **What:** Gathers URLs from AlienVault OTX, Wayback Machine, URLScan and Common Crawl. `--subs` includes subdomains; `inscope` removes the excluded ones.
            * **Why:** Increases URL coverage from diverse sources, including subdomains that are no longer live.

        8.  **Waybackurls:**
             ```bash
             cat domains.txt | waybackurls | inscope | anew allurls.txt
             ```
            * **What:** Another tool using Wayback Machine
            *  **Why**: Gets more Urls

        9.  **Unique URLs:**
            *Based off of @Coffinxp's method*
            ```bash
            cat allurls.txt | uro > filterparams.txt
            ```
            *   **What:** `uro` removes near-duplicate URLs (same path, different parameter values).
            *   **Why:** Cuts the list down to unique endpoints and parameters for everything that follows.

            If `filterparams.txt` is huge (over 100,000 lines), **copy sort.py to the target directory** and run it:
            ```bash
            cp ~/tools/WebRecon-Arsenal/sort.py .
            python3 sort.py
            ```

        10. **Filter for Potentially Sensitive Files:**
            ```bash
            cat allurls.txt | grep -iE "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.bak|\.yml|\.json|\.gz|\.rar|\.zip|\.config|\.env|\.sql" >> sens1.txt
            ```
            *   **What:** Filters URLs based on extensions associated with sensitive data.
            *   **Why:** Prioritizes URLs likely to contain sensitive information.

        11. **Extract JavaScript Files:**
            ```bash
            cat allurls.txt | grep -iE "\.js(\?|$)" | sort -u >> alljs.txt
            ```
            *   **What:** Isolates URLs pointing to JavaScript files.
            *   **Why:** JS files often contain valuable information for attackers.

        12. **Extract URLs from JavaScript (subjs):**
            ```bash
            cat alljs.txt | subjs | inscope | anew allurls.txt
            ```
            *   **What:** Parses JS code to extract embedded URLs, keeping only in-scope ones.
            *   **Why:** Finds URLs loaded dynamically by JS, often missed by crawlers.

        13. **Hidden Parameters (paramvoid):**
            ```bash
            cat filterparams.txt | grep -viE "\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ico)(\?|$)" | sed 's/?.*//' | sort -u > endpoints.txt
            paramvoid -i endpoints.txt -oJ paramvoid_results.json
            ```
            *   **What:** [paramvoid](https://github.com/CypherNova1337/paramvoid) learns what a normal response looks like, then tests its built-in wordlist in batches and reports the parameters that change the response.
            *   **Why:** Parameters the app reads but never links to (`debug`, `admin`, `is_staff`, `user_id`) are where access-control bugs and hidden debug modes live.
            *   **Note:** Add `-headers 'Cookie: session=...'` to test the logged-in surface — that's usually the interesting half. A second pass with `-casing likeThis` or `-casing like_this` finds parameters a single pass misses.

    *   **Phase 4: Directory and File Brute-Forcing**

        14. **Dirsearch (General Wordlist):**
            ```bash
            dirsearch -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w ~/tools/wordlists/onelistforall.txt
            ```
            *   **What:** Tries common directory/file names using a wordlist. `-l` targets live subdomains. `-x` excludes error codes. `-R` sets recursion depth. `--random-agent` helps avoid detection. `-t` is concurrency. `-F` follows redirects. `-w` specifies the wordlist.
            *   **Why:** Finds hidden content not linked from the website.
            *   **Note:** This step can take a *significant* amount of time, especially with a large wordlist like `onelistforall.txt` and a deep recursion level.  However, it can be run in the background while you proceed with other reconnaissance steps.  Using it with `dirsearch` can effectively map out the entire directory structure of the target application, potentially revealing a goldmine of hidden functionality and sensitive files – think of it as building your own detailed "blueprint" of the website.  This is why the output file is named `directory.txt`.

        15. **Dirsearch (Targeted Extensions - Iterative):**  Run this loop in your terminal.
            ```bash
            while read -r subdomain; do
            dirsearch -u "$subdomain" -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql.gz,sql.zip,sql.tar.gz,sql~,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,xml -x 500,502,429,404,400 -R 2 --random-agent -t 20 -F -o "dirsearch_extensions_$(echo "$subdomain" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            done < subdomains_alive.txt
            ```
            *   **What:**  Runs `dirsearch` for *each* live subdomain, focusing on specific file extensions (`-e`).
            *   **Why:** Targets potentially sensitive file types (configs, backups, etc.).
            *   **Note:** This iterative approach, while also potentially time-consuming, can be run concurrently with other tasks.  It's a more focused attack than the general brute-force, increasing the chances of finding specific types of sensitive files on each subdomain.  Because it runs individually for each subdomain, the output is organized into separate files (`dirsearch_extensions_<subdomain>.txt`), making analysis easier.

    *   **Phase 5: JavaScript Analysis**

        16. **Download the JavaScript:**
            ```bash
            mkdir -p js
            cat alljs.txt | inscope | while read -r url; do
                curl -sk "$url" -o "js/$(echo "$url" | md5sum | cut -c1-16).js"
            done
            ```
            *   **What:** Saves a local copy of every in-scope JS file.
            *   **Why:** The next steps scan files on disk, and you'll want them for manual review anyway.

        17. **Secrets (secretscan.py):**
            ```bash
            python3 ~/tools/Personal_Scipts/recon/secretscan.py -r js -o secrets.jsonl
            ```
            *   **What:** [secretscan.py](https://github.com/CypherNova1337/Personal_Scipts) matches known credential formats (AWS, GCP, GitHub, Slack, Stripe, JWT, private keys) and scores Shannon entropy to catch unknown high-randomness tokens.
            *   **Why:** Finds potentially exposed credentials, with far less noise than keyword matching.

        18. **Firebase and DOM Sinks (gf):**
            ```bash
            gf firebase js/ > firebase_hits.txt
            gf js-sinks js/ > js_sinks.txt
            ```
            *   **What:** Finds Firebase config (`firebaseConfig`, `projectId`, `.firebaseio.com`) and the places JS writes into the page or executes strings (`innerHTML`, `eval`, `location.href` ...).
            *   **Why:** Firebase projects are frequently misconfigured, and sinks are where DOM XSS starts.

            If you find a Firebase project ID, check it with [Firebase_Nuclei](https://github.com/CypherNova1337/Firebase_Nuclei):
            ```bash
            nuclei -t ~/tools/Firebase_Nuclei/firebase-discovery.yaml -u <FIREBASE_PROJECT_ID>
            ```

        19. **Source Maps (sourcemapper):**
            ```bash
            cat alljs.txt | inscope | while read -r url; do
                sourcemapper -jsurl "$url" -output "sourcemaps/$(echo "$url" | md5sum | cut -c1-16)"
            done
            ```
            *   **What:** When a JS file references a source map, [sourcemapper](https://github.com/cyphernova1337/sourcemapper) rebuilds the original source tree from it.
            *   **Why:** Original source has comments, internal routes and logic that minified bundles hide. Run `secretscan.py -r sourcemaps` on the result too.

        20. **Code Specter (Manual):** Install the [Code-Specter](https://github.com/CypherNova1337/Code-Specter) bookmarklet and click it on the target's key pages, especially behind a login.
            *   **What:** Reports developer notes and user-controlled input flowing into `innerHTML`, `eval` or `document.write`, right in the browser.
            *   **Why:** It sees the JS that's actually loaded in your session, including what an anonymous crawler never gets.

    *   **Phase 6: Vulnerability Scanning with Nuclei**

        21. **Nuclei (Personal Templates):**
            ```bash
            nuclei -list subdomains_alive.txt -t ~/tools/Personal_Nuclei_Templates/ -o nuclei_personal.txt
            ```
            *   **What:** Runs my [Personal_Nuclei_Templates](https://github.com/CypherNova1337/Personal_Nuclei_Templates): exposures (`.env`, `.git`, cloud credentials, backups, source maps), misconfigurations (CORS, CRLF, debug modes, actuators), CVEs, takeovers and technology discovery.
            *   **Why:** Each template only fires on corroborated evidence, so the results are worth triaging. Start here.

        22. **Nuclei (DAST Fuzzing):**
            ```bash
            cat filterparams.txt | nuclei -t ~/tools/Personal_Nuclei_Templates/vulnerabilities/ -t ~/tools/Personal_Nuclei_Templates/fuzzing/ -dast -o nuclei_dast.txt
            ```
            *   **What:** Fuzzes the query parameters in your URLs for SQLi, LFI, SSRF, SSTI and open redirects.
            *   **Why:** Catches the common injection classes across every parameter at once, before the dedicated tools in Phase 7 go deeper.

        23. **Nuclei (JS Exposures):**
            ```bash
            cat alljs.txt | inscope | nuclei -t ~/nuclei-templates/http/exposures/ -c 30 -o nuclei_js_exposures.txt
            ```
            *   **What:** Scans JS files for common exposures using the community templates.
            *   **Why:** Identifies potential security issues in JavaScript code.

        24. **Nuclei (General CVEs, OSINT, Tech):**
            ```bash
            nuclei -list subdomains_alive.txt -tags cve,osint,tech -o nuclei_general.txt
            ```
            *   **What:** Broad scan for known vulnerabilities, gathers OSINT data, and identifies technologies.
            *   **Why:** Identifies known exploits and technology details for targeted attacks.

    *   **Phase 7: Specialized Checks and Tools**

        25. **Subdomain Takeover:**
            ```bash
            inscope subdomains.txt | nuclei -t ~/tools/Personal_Nuclei_Templates/takeovers/ -o subdomaintakeover.txt
            ```
            *   **What:** Checks every subdomain (live or not) for dangling DNS pointing at unclaimed services.
            *   **Why:** Prevents attackers from hijacking subdomains. Dead subdomains are the ones that get taken over, so this uses `subdomains.txt`, not just the live list.

        26. **CORS, CRLF and Hop-by-Hop Headers (webscan.py):**
            ```bash
            python3 ~/tools/Personal_Scipts/exploit/webscan.py all -i subdomains_alive.txt -o webscan_findings.jsonl
            ```
            *   **What:** [webscan.py](https://github.com/CypherNova1337/Personal_Scipts) tests CORS (reflected origin, `null`, prefix/suffix/subdomain bypasses, unescaped-dot regex, wildcard with credentials), CRLF injection, and front ends that let `Connection:` strip headers.
            *   **Why:** CORS issues allow unauthorized data access, CRLF leads to header and response manipulation, and hop-by-hop abuse can bypass header-based access controls. Replaces Corsy and the separate CORS/CRLF Nuclei runs.

        27. **Blind SSRF and Open Redirects (NovaLure):**
            ```bash
            python3 ~/tools/NovaLure/NovaLure.py -i filterparams.txt --skip-assetfinder --skip-httprobe -o novalure_report.md
            ```
            *   **What:** [NovaLure](https://github.com/CypherNova1337/NovaLure) sprays URL-shaped parameters and headers with Interactsh callback URLs, and reports anything that phones home. It fuzzes open redirects in the same pass.
            *   **Why:** Blind SSRF never shows in the response. `--skip-assetfinder` matters: you already have your subdomains, and NovaLure's own discovery doesn't know about `out_of_scope.txt`.

        28. **LFI (LFI-Machine):**
            ```bash
            cat filterparams.txt | gf lfi | inscope > lfi_candidates.txt
            lfimachine -l lfi_candidates.txt -o lfi_loot/ --json lfi_results.json
            ```
            *   **What:** [LFI-Machine](https://github.com/CypherNova1337/LFI-Machine) fingerprints the stack, learns the target's normal and error responses, then adapts traversal depth and encoding until a payload survives.
            *   **Why:** It confirms a hit by the *structure* of what came back, so base64 and wrapped responses still register — the ones a `grep root:` approach misses.

        29. **SQL Injection (SmartSQL):**
            ```bash
            cat filterparams.txt | gf sqli | inscope > sqli_candidates.txt
            while read -r url; do smartsql -u "$url" --random-agent; done < sqli_candidates.txt | tee smartsql_results.txt
            ```
            *   **What:** [SmartSQL](https://github.com/CypherNova1337/SmartSQL) tests every parameter with boolean, error, time and union techniques, and watches how the target blocks it — escalating obfuscation when blocked and backing off when throttled.
            *   **Why:** No need to pick the right tamper script up front.

        30. **RCE, SSTI and Command Injection (VoidStrike):**
            ```bash
            cat filterparams.txt | gf rce | inscope > rce_candidates.txt
            cat filterparams.txt | gf ssti | inscope | anew rce_candidates.txt
            cat rce_candidates.txt | xargs voidstrike scan -s scope.yaml -o voidstrike-results
            ```
            *   **What:** [VoidStrike](https://github.com/CypherNova1337/VoidStrike) covers command injection, SSTI, code injection, expression language/JNDI, deserialisation and upload in one pass, with out-of-band confirmation.
            *   **Why:** RCE hides in many unrelated shapes. Copy `scope.example.yaml` from the VoidStrike repo to `scope.yaml`, put `*.target.com` under `in_scope` and your `out_of_scope.txt` hosts under `out_of_scope`.

        31. **XSS (dalfox):** Replace `your_xss_endpoint_here` with your blind XSS collaborator URL.
            ```bash
            cat filterparams.txt | gf xss | inscope | dalfox pipe -b your_xss_endpoint_here -o dalfox_xss.txt
            ```
            *   **What:**  Finds reflected, stored and blind Cross-Site Scripting (XSS) vulnerabilities in the parameters `gf xss` flags.
            *   **Why:** Prevents attackers from injecting malicious scripts.

        32. **IDOR (Auto-IDOR):** Needs two accounts on the target.
            ```bash
            cat filterparams.txt | gf idor | inscope > idor_candidates.txt
            auto-idor quick -u 'https://app.target.com/api/invoices/{id}' --token-a "$USER_A_JWT" --token-b "$USER_B_JWT" --owns-a 1041,1042 --owns-b 2001,2002
            ```
            *   **What:** [Auto-IDOR](https://github.com/CypherNova1337/Auto-IDOR) logs in as both users, asks each for the other's objects, and compares the content. `{id}` is the slot it swaps. Use `idor_candidates.txt` to pick endpoints, or `-r request.txt` to test a request captured in Burp.
            *   **Why:** A finding means user A actually received user B's data — not just "an endpoint returned 200".

    *   **Phase 8: Infrastructure**

        33. **Origin IPs Behind a CDN (VoidOrigin):**
            ```bash
            python3 ~/tools/VoidOrigin/voidorigin.py --targets domains.txt -o voidorigin.json
            ```
            *   **What:** [VoidOrigin](https://github.com/CypherNova1337/VoidOrigin) gathers candidate IPs from certificate transparency, a subdomain brute force and Shodan (`export SHODAN_API_KEY=...`), removes known CDN ranges, then connects to each candidate presenting the target's hostname and scores how well it matches the real site.
            *   **Why:** A reachable origin means talking to the app with the WAF and rate limits stepped over. Check the program's rules on testing origin IPs directly.

        34. **VPN and Remote-Access Gateways (VPNFinder):**
            ```bash
            while read -r domain; do
                python3 ~/tools/VPNFinder/vpn-finder.py "$domain" --min-confidence 70 -o "vpnfinder_$domain.json"
            done < domains.txt
            ```
            *   **What:** [VPNFinder](https://github.com/CypherNova1337/VPNFinder) finds FortiGate, GlobalProtect, Cisco ASA, Citrix, Pulse/Ivanti and similar gateways, names the product with a confidence score, and maps it to relevant CVEs.
            *   **Why:** These are the front door to the internal network, with a long history of actively exploited bugs. Check its findings against `out_of_scope.txt` before going further — it discovers hosts on its own. Identifying a portal is recon; trying credentials against it is not.

        35. **Full Port Scan with Naabu + Nmap:**
            ```bash
            naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC -Pn' -o naabu-full.txt
            ```
            *   **What:** Performs a port scan and service version detection. `-nmap-cli` uses Nmap for detailed scanning. `-Pn` skips host discovery (important if ICMP is blocked).
            *   **Why:** Identifies open ports and running services, revealing potential attack vectors.

    *   **Phase 9: Virtual Host Discovery**

        36. **Extract IPs from naabu results:**
            ```bash
            grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' naabu-full.txt | sort -u > ips.txt
            ```
            * **What**: Gets the IP addresses
            *   **Why**: used for virtual host discovery

        37. **Vhost Discovery (ffuf):** Run this loop.
            ```bash
            while read -r ip; do
                ffuf -w subdomains.txt:FUZZ -u https://$ip -H "Host: FUZZ" -fs 0 -o vhost_results_"$ip".json -of json
            done < ips.txt
            ```
            If you do not have any ips or wish to also vhost fuzz domains you can do:
            ```bash
            ffuf -u https://TARGET.com -w ~/tools/wordlists/vhost_wordlist.txt:VHOST -H "Host: VHOST.TARGET.com" -fs 0 -o domain_vhost.json -of json
            ```

            *   **What:**  Tries different `Host` headers to find virtual hosts on the same IP. `-w` is the wordlist, `-u` is the URL, `-H` sets the `Host` header, `-fs 0` filters out empty responses (add `-fs <size>` for the default page's size too). `subdomains.txt` already holds full hostnames, so the first loop uses them as-is.
            *   **Why:** Discovers hidden websites hosted on shared infrastructure.
            *   **Note:** Run any new hostnames you find through `inscope` before testing them.

    *   **Phase 10: Screenshotting (httpx)**

        38. **Take screenshots of live subdomains:**
            ```bash
            httpx -l subdomains_alive.txt -screenshot -srd screenshots
            ```
            * **What:** httpx renders each page in headless Chrome and saves a screenshot to `screenshots/`. This replaces aquatone, which is no longer maintained.
            * **Why:** Visual inspection can reveal interesting features, login panels, or outdated software versions that might not be apparent from automated scans.


## About `scope_filter.py`

Included in this repository, used throughout the guide via the `inscope` function.

1.  **Reads:** Hosts, URLs or tool output, one per line, from files or stdin. For lines like httpx's `https://host [200] [title]`, it uses the first field.
2.  **Keeps:** Only lines whose host is in `domains.txt` or a subdomain of one. With `--apex-only` (what [DomainDive](https://github.com/CypherNova1337/DomainDive) uses), only the exact domains — no subdomains at all.
3.  **Removes:** Anything matching `out_of_scope.txt` — hosts (and everything under them), `*.` wildcards, and keywords.
4.  **Writes:** The surviving lines, unchanged and deduplicated, to stdout.

## About `sort.py`

Included in this repository is a Python script, `sort.py`, designed to process the output of parameter discovery. This script performs the following actions:

1.  **Reads:** It reads a file named `filterparams.txt`. This file should contain a list of URLs with parameters, one per line (generated by `uro` in step 9).
2.  **Sorts:** It sorts the lines alphabetically.
3.  **Limits (Optional):** If the number of lines is very large, it truncates the list to the first 100,000 entries. This is a practical consideration.
4.  **Writes:** It writes the sorted (and potentially truncated) list to a new file named `sorted_params_100000.txt`.
5.  **Credit:** Credit to @Coffinxp

**Why this is useful:**

*   **Organization:** Sorting parameters helps in identifying patterns and prioritizing testing efforts.
*   **Performance:**  Some tools may perform better with a smaller, more focused set of parameters. You can always use the original `filterparams.txt` if needed.

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
