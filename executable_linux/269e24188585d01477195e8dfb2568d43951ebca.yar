rule Linux_Hacktool_Flooder_7d5355da
{
	meta:
		author = "Elastic Security"
		id = "7d5355da-5fbd-46c0-8bd2-33a27cbcca63"
		fingerprint = "52882595f28e1778ee3b0e6bda94319f5c348523f16566833281f19912360270"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "03397525f90c8c2242058d2f6afc81ceab199c5abcab8fd460fabb6b083d8d20"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 83 EC 60 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 BF 0A 00 }

	condition:
		all of them
}
