rule Linux_Trojan_Mirai_804f8e7c
{
	meta:
		author = "Elastic Security"
		id = "804f8e7c-4786-42bc-92e4-c68c24ca530e"
		fingerprint = "1080d8502848d532a0b38861437485d98a41d945acaf3cb676a7a2a2f6793ac6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 804f8e7c"
		filetype = "executable"

	strings:
		$a = { 31 ED 81 E1 FF 00 00 00 89 4C 24 58 89 EA C6 46 04 00 C1 FA 1F }

	condition:
		all of them
}
