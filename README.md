```
Subdomains v1.11 - Subdomain Finder

Reads a list of root domains, discovers their subdomains using public online
sources (certificate databases and passive DNS), and outputs the root domain
and all its subdomains.

No brute-force, no noise: only real subdomains found in public records.

USAGE:
  cat infile.lst | subdomains [OPTIONS]
  subdomains [OPTIONS] < infile.lst > outfile.lst

OPTIONS:
  -r, --resolved-only        Output only successfully resolved entries
  -w, --resolved-wan-only    Output only public (WAN) resolved entries
  -l, --resolved-lan-only    Output only private (LAN) resolved entries
  -d, --dns=SERVERS          Custom DNS servers (comma-separated, e.g. 8.8.8.8,1.1.1.1)
```
