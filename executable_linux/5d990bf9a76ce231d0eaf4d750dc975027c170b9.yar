rule Linux_Cryptominer_Generic_6dad0380
{
	meta:
		author = "Elastic Security"
		id = "6dad0380-7771-4fb9-a7e5-176eeb6fcfd7"
		fingerprint = "ffe022f42e98c9c1eeb3aead0aca9d795200b4b22f89e7f3b03baf96f18c9473"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "628b1cc8ccdbe2ae0d4ef621da047e07e2532d00fe3d4da65f0a0bcab20fb546"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 48 C1 E6 05 48 01 C6 48 39 F1 74 05 49 89 74 24 08 44 89 E9 48 C1 }

	condition:
		all of them
}
