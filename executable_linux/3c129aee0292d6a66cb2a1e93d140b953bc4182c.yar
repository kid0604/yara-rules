rule Linux_Generic_Threat_9cf10f10
{
	meta:
		author = "Elastic Security"
		id = "9cf10f10-9a5b-46b5-ae25-7239b8f1434a"
		fingerprint = "88b3122e747e685187a7b7268e22d12fbd16a24c7c2edb6f7e09c86327fc2f0e"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "d07c9be37dc37f43a54c8249fe887dbc4058708f238ff3d95ed21f874cbb84e8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 84 1E 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 52 C7 05 00 8B 44 24 }

	condition:
		all of them
}
