rule Linux_Cryptominer_Camelot_9ac1654b
{
	meta:
		author = "Elastic Security"
		id = "9ac1654b-f2f0-4d32-8e2a-be30b3e61bb0"
		fingerprint = "156c60ee17e9b39cb231d5f0703b6e2a7e18247484f35e11d3756a025873c954"
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
		$a = { CD 41 C1 CC 0B 31 D1 31 E9 44 89 D5 44 31 CD C1 C9 07 41 89 E8 }

	condition:
		all of them
}
