# Open Source Threat Intel Feeds
This repository contains Open Source freely usable Threat Intel feeds that can be used without additional requirements. The CSV [ThreatIntelFeeds.cvs](./ThreatIntelFeeds.csv) is stored in a structured manner based on the Vendor, Description, Category and the URL. The vendors offering ThreatIntelFeeds are described below. 
The following feed categories are available:
- SSL
- IP
- DNS
- URL
- MD5
- SHA1
- SHA256

# Combine Threat Intel in your EDR and SIEM
The feeds available in this repository can be used to perform threat hunting in your EDR or SIEM solution to hunt for malicious activity. For Defender For Endpoint and Sentinel some KQL hunting rules have already been written to be implemented in your EDR or SIEM. See: [KQL Hunting Queries](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/Threat%20Hunting)

# Abuse.ch
- https://sslbl.abuse.ch/blacklist/sslblacklist.csv
- https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
- https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
- https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv
- https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt
- https://threatfox.abuse.ch/downloads/hostfile/
- https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- https://feodotracker.abuse.ch/blocklist/
- https://bazaar.abuse.ch/export/txt/md5/recent/
- https://threatfox.abuse.ch/export/csv/md5/recent/
- https://bazaar.abuse.ch/export/txt/sha1/recent/
- https://bazaar.abuse.ch/export/txt/sha256/recent/
- https://threatfox.abuse.ch/export/csv/sha256/recent/

Terms of Service: https://sslbl.abuse.ch/blacklist/, https://feodotracker.abuse.ch/blocklist/

# Blocklist.de
- https://lists.blocklist.de/lists/all.txt
- https://lists.blocklist.de/lists/ssh.txt
- https://lists.blocklist.de/lists/mail.txt
- https://lists.blocklist.de/lists/apache.txt
- https://lists.blocklist.de/lists/imap.txt
- https://lists.blocklist.de/lists/bots.txt
- https://lists.blocklist.de/lists/bruteforcelogin.txt
- https://lists.blocklist.de/lists/strongips.txt

Terms of Service: https://www.blocklist.de/en/index.html
