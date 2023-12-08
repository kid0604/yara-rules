rule Linux_Trojan_Mirai_6e8e9257
{
	meta:
		author = "Elastic Security"
		id = "6e8e9257-a6d5-407a-a584-4656816a3ddc"
		fingerprint = "4bad14aebb0b8c7aa414f38866baaf1f4b350b2026735de24bcf2014ff4b0a6a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 6e8e9257"
		filetype = "executable"

	strings:
		$a = { 53 83 EC 04 8B 5C 24 18 8B 7C 24 20 8A 44 24 14 8A 54 24 1C 88 54 }

	condition:
		all of them
}
