#!/usr/bin/env python3
"""Sift dirsearch results down to what's worth looking at.

Reads every dirsearch report in the given folders (recursively) or files and
writes one combined, deduplicated file.

Sites that answer every path with a custom "not found" page produce thousands
of hits with the same status and size. Per host, any status + size pair seen at
least --threshold times is treated as that host's soft-404 and dropped. What's
left is the hits whose size stands out.

Redirects are grouped by where they point as well, so hundreds of paths that
all redirect to /login or /notfound are dropped, while real folders
(/admin -> /admin/, each to a different target) are kept.

    python3 dirsift.py DirSearch/ -o dirsearch_results.txt
    python3 dirsift.py DirSearch/ -t 5 --show-dropped

dirsearch rounds sizes (2KB, 1.5MB), so a real page that rounds to the same
size as a host's soft-404 is dropped with it. Lower -t, or check --show-dropped
on hosts that matter.
"""
import argparse
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

LINE = re.compile(r"^(\d{3})\s+(\S+)\s+(https?://\S+)(.*)$")
TIMING = re.compile(r"\(\d+(?:\.\d+)?m?s\)")
REDIRECT = re.compile(r"->\s*(\S+)")


def report_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                for name in sorted(names):
                    yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path
        else:
            print(f"dirsift: not found: {path}", file=sys.stderr)


def parse(files):
    hits = {}
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = LINE.match(line.strip())
                if not m:
                    continue
                status, size, url, rest = m.groups()
                rest = " ".join(TIMING.sub("", rest).split())
                hits.setdefault(url, (status, size, rest))
    return hits


def signature(status, size, rest):
    m = REDIRECT.search(rest)
    target = m.group(1).split("?", 1)[0] if m else ""
    return status, size, target


def origin(url):
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def main():
    p = argparse.ArgumentParser(description="Drop soft-404 noise from dirsearch results and merge them into one file.")
    p.add_argument("paths", nargs="+", help="dirsearch report folders (searched recursively) or files")
    p.add_argument("-o", "--output", default="dirsearch_results.txt", help="combined output file (default: %(default)s)")
    p.add_argument("-t", "--threshold", type=int, default=10,
                   help="per host, drop a status + size seen this many times or more (default: %(default)s)")
    p.add_argument("--show-dropped", action="store_true", help="list each dropped status + size per host")
    args = p.parse_args()

    hits = parse(report_files(args.paths))
    if not hits:
        sys.exit("dirsift: no dirsearch results found")

    by_host = defaultdict(list)
    for url, (status, size, rest) in hits.items():
        by_host[origin(url)].append((url, status, size, rest))

    kept, dropped_total = [], 0
    for host in sorted(by_host):
        rows = by_host[host]
        counts = Counter(signature(status, size, rest) for _, status, size, rest in rows)
        noise = {k for k, n in counts.items() if n >= args.threshold}
        for url, status, size, rest in rows:
            if signature(status, size, rest) in noise:
                dropped_total += 1
            else:
                kept.append((host, status, url, size, rest))
        if noise and args.show_dropped:
            for sig in sorted(noise):
                status, size, target = sig
                to = f" -> {target}" if target else ""
                print(f"  {host}: dropped {counts[sig]} x {status} {size}{to}", file=sys.stderr)

    kept.sort()
    with open(args.output, "w", encoding="utf-8") as out:
        for _, status, url, size, rest in kept:
            out.write(f"{status} {size:>7} {url}{(' ' + rest) if rest else ''}\n")

    print(f"dirsift: {len(hits)} unique hits across {len(by_host)} hosts, "
          f"dropped {dropped_total} as soft-404 noise, kept {len(kept)} -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
