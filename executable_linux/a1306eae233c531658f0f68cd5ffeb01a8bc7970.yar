rule Linux_Cryptominer_Generic_23a5c29a
{
	meta:
		author = "Elastic Security"
		id = "23a5c29a-6a8f-46f4-87ba-2a60139450ce"
		fingerprint = "1a7a86ff6e1666c2da6e6f65074bb1db2fe1c97d1ad42d1f670dd5c88023eecf"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { C1 48 29 D0 48 01 C0 4D 8B 39 48 29 C1 49 29 F8 48 8D 04 C9 4D 8D }

	condition:
		all of them
}
