# yara-rules

Crawling yara rules from multiple sources, cleans them, and adds some metadata using LLM.

**Pipeline:**

crawl --> clean --> enrich

**crawl:** get rules from various sources on github

**clean:** remove rules that are:
- syntactically incorrect,
- duplicates,
- dependent on other rules or use external variables,
- obsoleted rules, such as PEiD, etc.

**enrich:** use LLMs to add additional metadata such as OS, filetype, description.

**Yara rules sources:**

https://github.com/embee-research/Yara-detection-rules.git

https://github.com/FarghlyMal/Yara_Rules.git

https://github.com/rivitna/Malware.git

https://github.com/elastic/protections-artifacts.git

https://github.com/bartblaze/Yara-rules.git

https://github.com/airbnb/binaryalert.git

https://github.com/kevoreilly/CAPEv2.git

https://github.com/delivr-to/detections.git

https://github.com/mandiant/red_team_tool_countermeasures.git

https://github.com/Neo23x0/signature-base.git

https://github.com/f0wl/yara_rules.git

https://github.com/malpedia/signator-rules.git

https://github.com/Yara-Rules/rules.git

https://github.com/m-sec-org/d-eyes.git

https://github.com/ditekshen/detection.git

https://github.com/securitymagic/yara.git

https://github.com/RussianPanda95/Yara-Rules.git
