rule Linux_Cryptominer_Camelot_6a279f19
{
	meta:
		author = "Elastic Security"
		id = "6a279f19-3c9e-424b-b89e-8807f40b89eb"
		fingerprint = "1c0ead7a7f7232edab86d2ef023c853332254ce1dffe1556c821605c0a83d826"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "5b01f72b2c53db9b8f253bb98c6584581ebd1af1b1aaee62659f54193c269fca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 89 F3 89 D6 48 83 EC 30 48 89 E2 64 48 8B 04 25 28 00 00 00 48 89 44 }

	condition:
		all of them
}
