rule Linux_Trojan_Mirai_3fe3c668
{
	meta:
		author = "Elastic Security"
		id = "3fe3c668-89f4-4601-a167-f41bbd984ae5"
		fingerprint = "2a79caea707eb0ecd740106ea4bed2918e7592c1e5ad6050f6f0992cf31ba5ec"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 3fe3c668"
		filetype = "executable"

	strings:
		$a = { 00 84 C0 0F 95 C0 48 FF 45 E8 84 C0 75 E9 8B 45 FC C9 C3 55 48 }

	condition:
		all of them
}
