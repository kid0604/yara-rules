rule Linux_Cryptominer_Camelot_dd167aa0
{
	meta:
		author = "Elastic Security"
		id = "dd167aa0-80e0-46dc-80d1-9ce9f6984860"
		fingerprint = "2642e4c4c58d95cd6ed6d38bf89b108dc978a865473af92494b6cb89f4f877e2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { E7 F2 AE 4C 89 EF 48 F7 D1 48 89 CE 48 89 D1 F2 AE 48 89 C8 48 }

	condition:
		all of them
}
