rule Linux_Cryptominer_Malxmr_6671f33a
{
	meta:
		author = "Elastic Security"
		id = "6671f33a-03bb-40d8-b439-64a66082457d"
		fingerprint = "cb178050ee351059b083c6a71b5b1b6a9e0aa733598a05b3571701949b4e6b28"
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
		$a = { 4D 18 48 01 4B 18 5A 5B 5D C3 83 C8 FF C3 48 85 FF 49 89 F8 }

	condition:
		all of them
}
