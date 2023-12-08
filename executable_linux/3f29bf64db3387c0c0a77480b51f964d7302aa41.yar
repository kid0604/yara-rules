rule Linux_Cryptominer_Generic_9088d00b
{
	meta:
		author = "Elastic Security"
		id = "9088d00b-622a-4cbf-9600-6dfcf2fc0c2c"
		fingerprint = "85cbe86b9f96fc1b6899b35cc4aa16b66a91dc1239ed5f5cf3609322cec30f30"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "8abb2b058ec475b0b6fd0c994685db72e98d87ee3eec58e29cf5c324672df04a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 2C 1C 77 16 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 24 48 83 }

	condition:
		all of them
}
