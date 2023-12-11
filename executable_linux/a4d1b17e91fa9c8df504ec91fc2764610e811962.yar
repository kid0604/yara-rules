rule Linux_Trojan_Gafgyt_6122acdf
{
	meta:
		author = "Elastic Security"
		id = "6122acdf-1eef-45ea-83ea-699d21c2dc20"
		fingerprint = "283275705c729be23d7dc75056388ecae00390bd25ee7b66b0cfc9b85feee212"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 6122acdf"
		filetype = "executable"

	strings:
		$a = { E8 B0 00 FC 8B 7D E8 F2 AE 89 C8 F7 D0 48 48 89 45 F8 EB 03 FF }

	condition:
		all of them
}
