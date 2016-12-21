# magesecurityscanner
### Malware Detection Suite for Magento

The magesecurityscanner project is a scanner for known Magento malware. The scanner uses yara (http://virustotal.github.io/yara/) for malware scanning as well as customized whitelisting for known good magento core files to speed up scanning. If yara is not installed it will default back to using grep to find malware strings, however yara is recommened to be installed for more granular scanning.

Rules have been contributed by:
Magemojo - http://magemojo.com
Willem de Groot - https://github.com/gwillem/magento-malware-scanner

###Usage: ./magescecurityscan.sh <path to scan> <rules file> [<scan type>fast|standard|deep] [<scan precision> all|code] [<whitelist option> hash|size|none]

###Path to Scan
Defines the path to scan, recursively scans all subfolders

###Rules File
The rules file to use, yararules.yar and yararules-deep.yar are supplied. The deep scan file can include false positives and is used primarily for discovery of new malware.

###Scan Type
deep
..* scans files with all rules, includes loose rules for code obfuscation
..* includes sha1 whitelist
..* defaults to all precision
standard
..* scans files with rules with no known false positives
..* includes sha1 whitelist
..* defaults to code only precision
fast
..* scans files with rules with no known false positives
..* includes file size whitelist
..* defaults to code only precision
    
###Scan Precision
..* all - scans all files and subdirectories regardless of type
..* code - scans files with the following extensions php,phtml,js,html

###Whitelist Option
Defines the type of whitelist to use. Scans based on filesize could potentially be decieved however are mush faster than the hash method. Specifing none will scan all files.