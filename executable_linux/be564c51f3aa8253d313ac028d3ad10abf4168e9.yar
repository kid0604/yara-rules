rule Linux_Trojan_Gafgyt_d0c57a2e
{
	meta:
		author = "Elastic Security"
		id = "d0c57a2e-c10c-436c-be13-50a269326cf2"
		fingerprint = "3ee7d3a33575ed3aa7431489a8fb18bf30cfd5d6c776066ab2a27f93303124b6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 }

	condition:
		all of them
}
