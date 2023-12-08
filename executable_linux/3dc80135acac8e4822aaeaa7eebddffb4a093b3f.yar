rule Linux_Trojan_Mirai_3a56423b
{
	meta:
		author = "Elastic Security"
		id = "3a56423b-c0cf-4483-87e3-552beb40563a"
		fingerprint = "117d6eb47f000c9d475119ca0e6a1b49a91bbbece858758aaa3d7f30d0777d75"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 3a56423b"
		filetype = "executable"

	strings:
		$a = { 24 1C 8B 44 24 20 0F B6 D0 C1 E8 08 89 54 24 24 89 44 24 20 BA 01 00 }

	condition:
		all of them
}
