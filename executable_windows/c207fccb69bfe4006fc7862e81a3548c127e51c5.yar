rule Windows_Generic_Threat_c9003b7b
{
	meta:
		author = "Elastic Security"
		id = "c9003b7b-2e04-429c-a147-33aeb3e474ac"
		fingerprint = "3e0437dbb5534dfd9f5ee68c50b0f868a88fadc0ded897cb595239456ae3bbb3"
		creation_date = "2024-10-10"
		last_modified = "2024-11-26"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ff2a1def8c4fae4166e249edab62d73f44ba3c05d5e3c9fda11399bfe1fcee6c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC B8 01 00 00 49 89 CE 4C 8B 41 28 48 8B 51 48 E8 FE FE FF FF 48 89 C6 4D 8B 46 28 49 8B 56 50 4C 89 F1 E8 EB FE FF FF 48 89 C7 4D 8B 46 28 49 8B 96 E8 01 00 00 4C 89 F1 E8 D5 FE FF FF }

	condition:
		all of them
}
