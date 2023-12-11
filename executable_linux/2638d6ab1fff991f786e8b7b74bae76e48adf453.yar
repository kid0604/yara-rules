rule Linux_Cryptominer_Uwamson_41e36585
{
	meta:
		author = "Elastic Security"
		id = "41e36585-0ef1-4896-a887-dac437c716a5"
		fingerprint = "ad2d4a46b9378c09b1aef0f2bf67a990b3bacaba65a5b8c55c2edb0c9a63470d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Uwamson"
		reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Uwamson malware"
		filetype = "executable"

	strings:
		$a = { F8 03 48 C1 FF 03 4F 8D 44 40 FD 48 0F AF FE 49 01 F8 4C 01 C2 4C }

	condition:
		all of them
}
