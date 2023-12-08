rule Linux_Trojan_Mirai_88de437f
{
	meta:
		author = "Elastic Security"
		id = "88de437f-9c98-4e1d-96c0-7b433c99886a"
		fingerprint = "c19eb595c2b444a809bef8500c20342c9f46694d3018e268833f9b884133a1ea"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with fingerprint 88de437f"
		filetype = "executable"

	strings:
		$a = { 24 08 8B 4C 24 04 85 D2 74 0D 31 C0 89 F6 C6 04 08 00 40 39 D0 }

	condition:
		all of them
}
