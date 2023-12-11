rule Linux_Trojan_Gafgyt_6a510422
{
	meta:
		author = "Elastic Security"
		id = "6a510422-3662-4fdb-9c03-0101f16e87cd"
		fingerprint = "8ee116ff41236771cdc8dc4b796c3b211502413ae631d5b5aedbbaa2eccc3b75"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 6a510422"
		filetype = "executable"

	strings:
		$a = { 0B E5 24 30 1B E5 2C 30 0B E5 1C 00 00 EA 18 30 1B E5 00 30 }

	condition:
		all of them
}
