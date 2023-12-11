rule Linux_Trojan_Swrort_22c2d6b6
{
	meta:
		author = "Elastic Security"
		id = "22c2d6b6-d100-4310-87c4-3912a86bdd40"
		fingerprint = "d2b16da002cb708cb82f8b96c7d31f15c9afca69e89502b1970758294e91f9a4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Swrort"
		reference_sample = "6df073767f48dd79f98e60aa1079f3ab0b89e4f13eedc1af3c2c073e5e235bbc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Swrort"
		filetype = "executable"

	strings:
		$a = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 51 6A 04 54 6A 02 }

	condition:
		all of them
}
