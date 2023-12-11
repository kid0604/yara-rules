rule Linux_Cryptominer_Generic_98ff0f36
{
	meta:
		author = "Elastic Security"
		id = "98ff0f36-5faf-417a-9431-8a44e9f088f4"
		fingerprint = "b25420dfc32522a060dc8470315409280e3c03de0b347e92a5bc6c1a921af94a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "4c14aaf05149bb38bbff041432bf9574dd38e851038638aeb121b464a1e60dcc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 45 A8 8B 00 89 C2 48 8B 45 C8 48 01 C2 8B 45 90 48 39 C2 7E 08 8B }

	condition:
		all of them
}
