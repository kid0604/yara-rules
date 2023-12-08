rule Linux_Cryptominer_Generic_050ac14c
{
	meta:
		author = "Elastic Security"
		id = "050ac14c-9aef-4212-97fd-e2a21c2f62e2"
		fingerprint = "6f0a5a5d3cece7ae8db47ef5e1bbbea02b886e865f23b0061c2d346feb351663"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 47 08 49 3B 47 10 74 3C 48 85 C0 74 16 48 8B 13 48 89 10 48 8B }

	condition:
		all of them
}
