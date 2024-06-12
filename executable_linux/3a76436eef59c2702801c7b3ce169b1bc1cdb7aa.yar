rule Linux_Generic_Threat_b8b076f4
{
	meta:
		author = "Elastic Security"
		id = "b8b076f4-c64a-400b-80cb-5793c97ad033"
		fingerprint = "f9c6c055e098164d0add87029d03aec049c4bed2c4643f9b4e32dd82f596455c"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "4496e77ff00ad49a32e090750cb10c55e773752f4a50be05e3c7faacc97d2677"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 44 0F 11 7C 24 2E 44 0F 11 7C 24 2F 44 0F 11 7C 24 3F 44 0F 11 7C 24 4F 44 0F 11 7C 24 5F 48 8B 94 24 C8 00 00 00 48 89 54 }

	condition:
		all of them
}
