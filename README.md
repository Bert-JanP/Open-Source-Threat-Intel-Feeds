# Open Source Threat Intel Feeds [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Open%20Source%20Threat%20Intel%20Feeds%20Listed!%20Compatible%20with%20EDR%20and%20SIEM%20Solutions!&url=https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
This repository contains Open Source freely usable Threat Intel feeds that can be used without additional requirements. The CSV [ThreatIntelFeeds.cvs](./ThreatIntelFeeds.csv) is stored in a structured manner based on the Vendor, Description, Category and the URL. The vendors offering ThreatIntelFeeds are described below. 
The following feed categories are available:
- SSL
- IP
- DNS
- URL
- MD5
- SHA1
- SHA256
- CVEID

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

# Alienvault
- http://reputation.alienvault.com/reputation.data

# Cisco Talos
- http://www.talosintelligence.com/documents/ip-blacklist

# Binarydefense
- https://www.binarydefense.com/banlist.txt

# Github based feeds
- https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv
- https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/cobaltstrike-servers.csv

# CISA
- https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

# MISP Feed CERT-FR
- https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv
