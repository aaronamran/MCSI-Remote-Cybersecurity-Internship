# TheHarvester.py
TheHarvester is a useful OSINT (Open Source Intelligence) tool that helps cybersecurity professionals and researchers gather information like domains, email addresses, usernames, and subdomains from public sources


## Create A Spreadsheet To Document The Results
Headings required: Target Domain, Discovery Date, Name, Email, URLs, Subdomains, IP

Submitted spreadsheet will not be linked here as it is considered confidential


## Perform Reconnaisance With TheHarvester
- Extract relevant email addresses
- Identify URLs
- Gather a list of subdomains belonging to the target domain
- Perform DNS brute forcing to discover hidden subdomains or domain variations

- The command theharvester is deprecated, use theHarvester instead:
  ```
  theHarvester -d eccouncil.org -s -n -c -b all
  ```

Screenshot of commands used on the target website: <br/>
![image](https://github.com/user-attachments/assets/8a459588-f1e7-4e7e-bb50-776a4e90feb7)

- `-d targetdomain.com`: specifies the target domain to be searched
- `-s`: performs a Shodan search (requires API keys in `api-keys.yaml` file)
- `-n`: skips reverse DNS resolution (does not perform looking up hostnames from IP addresses) to save time or avoid issues with DNS resolution
- `-c`: performs a DNS brute-force (guesses subdomains and hosts by using wordlists/dictionary)
- `-b all`: specifies to use all search engines/data sources

