Subdomains v1.8 - Subdomain Finder

Reads a list of root domains, discovers their subdomains using public online
sources (certificate databases and passive DNS), and outputs the root domain
and all its subdomains.

No brute-force, no noise: only real subdomains found in public records.

USAGE:
  cat domains.lst | subdomains
  subdomains < domains.lst
  subdomains < domains.lst > subdomains.lst
