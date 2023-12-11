rule Linux_Trojan_Gafgyt_d2953f92
{
	meta:
		author = "Elastic Security"
		id = "d2953f92-62ee-428d-88c5-723914c88c6e"
		fingerprint = "276c6d62a8a335d0e2421b6b5b90c2c0eb69eec294bc9fcdeb7743abbf08d8bc"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 1B E5 2A 00 53 E3 0A 00 00 0A 30 30 1B E5 3F 00 53 E3 23 00 }

	condition:
		all of them
}
