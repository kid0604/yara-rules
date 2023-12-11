rule Linux_Cryptominer_Generic_ea5703ce
{
	meta:
		author = "Elastic Security"
		id = "ea5703ce-4ad4-46cc-b253-8d022ca385a3"
		fingerprint = "a58a41ab4602380c0989659127d099add042413f11e3815a5e1007a44effaa68"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "bec6eea63025e2afa5940d27ead403bfda3a7b95caac979079cabef88af5ee0b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 0F 94 C0 EB 05 B8 01 00 00 00 44 21 E8 48 8B 4C 24 08 64 48 33 0C 25 28 00 }

	condition:
		all of them
}
