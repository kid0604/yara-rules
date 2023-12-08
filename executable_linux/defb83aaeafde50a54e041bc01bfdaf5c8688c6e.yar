rule Linux_Cryptominer_Malxmr_d13544d7
{
	meta:
		author = "Elastic Security"
		id = "d13544d7-4834-4ce7-9339-9c933ee51b2c"
		fingerprint = "02e1be4a7073e849b183851994c83f1f2077fe74cbcdd0b3066999d0c9499a09"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 51 50 4D 21 EB 4B 8D 0C 24 4C 89 54 24 90 4C 89 DD 48 BA AA AA AA AA AA AA }

	condition:
		all of them
}
