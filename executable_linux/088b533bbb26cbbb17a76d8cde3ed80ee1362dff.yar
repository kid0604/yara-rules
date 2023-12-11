rule Linux_Trojan_Mirai_6a77af0f
{
	meta:
		author = "Elastic Security"
		id = "6a77af0f-31fa-4793-82aa-10b065ba1ec0"
		fingerprint = "4e436f509e7e732e3d0326bcbdde555bba0653213ddf31b43cfdfbe16abb0016"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 6a77af0f"
		filetype = "executable"

	strings:
		$a = { 31 D1 89 0F 48 83 C7 04 85 F6 7E 3B 44 89 C8 45 89 D1 45 89 C2 41 }

	condition:
		all of them
}
