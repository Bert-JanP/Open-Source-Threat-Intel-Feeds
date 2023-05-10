# Free Threat Intel/IOC Feeds [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Open%20Source%20Threat%20Intel%20Feeds%20Listed!%20Compatible%20with%20EDR%20and%20SIEM%20Solutions!&url=https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
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

# Contributions 
Contributions are much appreciated to make this list with free Threat Intel/IOC feeds as big and as up to date as possible. You can contribute by creating a pull request. This PR must contain the following content:
1. Add the link of the feed in the README.md file. If there is not a section yet in which the source fits, create a new section.
2. Add the details to the ThreatIntelFeeds.csv file, the format which is used is shown below. The Category refers to the feed categories shown above.
    ```
    Vendor;Description;Category;Url
    ```
3. Lastly, the source must be free and usable without any account or API token needed. 

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
- https://urlhaus.abuse.ch/downloads/csv_recent/

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

# IPSum
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt
- https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt

# C2IntelFeeds
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/IPC2s-30day.csv
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2s-30day-filter-abused.csv
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURL-30day-filter-abused.csv
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURL-filter-abused.csv
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURLwithIP-30day-filter-abused.csv
- https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2s.csv

# C2-Tracker
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Brute%20Ratel%20C4%20IPs.txt
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Cobalt%20Strike%20C2%20IPs.txt
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Posh%20C2%20IPs.txt
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Sliver%20C2%20IPs.txt
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Metasploit%20Framework%20C2%20IPs.txt
- https://github.com/montysecurity/C2-Tracker/blob/main/data/Havoc%20C2%20IPs.txt

# Carbon Black
- https://github.com/carbonblack/active_c2_ioc_public/blob/main/cobaltstrike/actor-specific/cobaltstrike_luckymouse_ta428.csv
- https://github.com/carbonblack/active_c2_ioc_public/blob/main/cobaltstrike/actor-specific/cobaltstrike_pyxie.csv
- https://github.com/carbonblack/active_c2_ioc_public/blob/main/shadowpad/shadowpad_202209.tsv

# Phishing Army
- https://phishing.army/download/phishing_army_blocklist.txt
- https://phishing.army/download/phishing_army_blocklist_extended.txt

# Alienvault
- http://reputation.alienvault.com/reputation.data

# Cisco Talos
- http://www.talosintelligence.com/documents/ip-blacklist

# Binarydefense
- https://www.binarydefense.com/banlist.txt

# CISA
- https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

# eCrimeLabs 
- https://feeds.ecrimelabs.net/data/metasploit-cve

# MISP Feed CERT-FR
- https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv

# Mr. Looquer IOC Feed
- https://iocfeed.mrlooquer.com/feed.csv

# SNORT
- https://snort.org/downloads/ip-block-list

# CyberCure
- https://api.cybercure.ai/feed/get_hash?type=csv

# Other Github based feeds
- https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv
- https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/cobaltstrike-servers.csv

# Notable links
- https://github.com/eset/malware-ioc
- https://www.misp-project.org/feeds/
- https://github.com/MISP/MISP/blob/2.4/app/files/feed-metadata/defaults.json
