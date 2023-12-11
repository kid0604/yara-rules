rule Linux_Cryptominer_Generic_9d531f70
{
	meta:
		author = "Elastic Security"
		id = "9d531f70-c42f-4e1a-956a-f9ac43751e73"
		fingerprint = "2c6019f7bc2fc47d7002e0ba6e35513950260b558f1fdc732d3556dabbaaa93d"
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
		$a = { 49 10 58 00 10 D4 34 80 08 30 01 20 02 00 B1 00 83 49 23 16 54 }

	condition:
		all of them
}
