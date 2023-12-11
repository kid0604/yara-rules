rule Linux_Trojan_Mirai_24c5b7d6
{
	meta:
		author = "Elastic Security"
		id = "24c5b7d6-1aa8-4d8e-9983-c7234f57c3de"
		fingerprint = "3411b624f02dd1c7a0e663f1f119c8d5e47a81892bb7c445b7695c605b0b8ee2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "7c2f8ba2d6f1e67d1b4a3a737a449429c322d945d49dafb9e8c66608ab2154c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 24c5b7d6"
		filetype = "executable"

	strings:
		$a = { 54 38 1C 80 FA 3E 74 25 80 FA 3A 74 20 80 FA 24 74 1B 80 FA 23 }

	condition:
		all of them
}
