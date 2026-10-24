#!/usr/bin/env python3
"""Keep only in-scope lines from recon output.

Reads hosts, URLs or tool output (one item per line; for lines like httpx's
`https://host [200] [title]` the first field is used) from files or stdin and
prints only the lines whose host is in scope.

    -s domains.txt        in-scope roots, one per line
    -x out_of_scope.txt   exclusions, one per line (optional)
    --apex-only           host must equal a root exactly; no subdomains

Without --apex-only, a host is in scope when it is a root or any subdomain of
one. Exclusions always win:

    sub.domain.com        removes that host and everything under it
    *.dev.domain.com      removes everything under dev.domain.com
    contact               anything without a dot (or containing a /) is a
    /admin/billing        keyword, removing any line that contains it
"""
import argparse
import sys
from urllib.parse import urlsplit


def read_list(path):
    entries = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                entries.append(line)
    return entries


def host_of(item):
    item = item.strip().split()[0] if item.strip() else ""
    if "://" not in item:
        item = "//" + item
    try:
        host = urlsplit(item).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def under(host, root):
    return host == root or host.endswith("." + root)


def main():
    p = argparse.ArgumentParser(description="Keep only in-scope lines from recon output.")
    p.add_argument("files", nargs="*", help="Input files (default: stdin)")
    p.add_argument("-s", "--scope", required=True, help="In-scope roots, one per line")
    p.add_argument("-x", "--exclude", help="Out-of-scope hosts, wildcards or keywords, one per line")
    p.add_argument("--apex-only", action="store_true", help="Only the exact roots; drop every subdomain")
    args = p.parse_args()

    roots = [host_of(r[2:] if r.startswith("*.") else r) for r in read_list(args.scope)]
    roots = [r for r in roots if r]
    ex_hosts, ex_wild, ex_words = [], [], []
    if args.exclude:
        for e in read_list(args.exclude):
            if e.startswith("*."):
                ex_wild.append(e[2:])
            elif "." in e and "/" not in e:
                ex_hosts.append(host_of(e))
            else:
                ex_words.append(e)

    def in_scope(line):
        host = host_of(line)
        if not host:
            return False
        if args.apex_only:
            if host not in roots:
                return False
        elif not any(under(host, r) for r in roots):
            return False
        if any(under(host, e) for e in ex_hosts) or any(host.endswith("." + w) for w in ex_wild):
            return False
        low = line.lower()
        return not any(w in low for w in ex_words)

    streams = [open(f, encoding="utf-8", errors="replace") for f in args.files] or [sys.stdin]
    seen = set()
    for stream in streams:
        for line in stream:
            line = line.rstrip("\n")
            if line and line not in seen and in_scope(line):
                seen.add(line)
                print(line)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
