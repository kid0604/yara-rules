rule Linux_Trojan_Gafgyt_6ae4b580
{
	meta:
		author = "Elastic Security"
		id = "6ae4b580-f7cf-4318-b584-7ea15f10f5ea"
		fingerprint = "279e344d6da518980631e70d7b1ded4ff1b034d24e4b4fe01b36ed62f5c1176c"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 6ae4b580"
		filetype = "executable"

	strings:
		$a = { 30 0B E5 3C 20 1B E5 6C 32 1B E5 03 00 52 E1 01 00 00 DA 6C }

	condition:
		all of them
}
