rule Windows_Generic_Threat_b577c086
{
	meta:
		author = "Elastic Security"
		id = "b577c086-37bd-4227-8cde-f15e2ce0d0ae"
		fingerprint = "0de3cab973de067f2c10252bf761ced353de57c03c4b2e95db05ee3ca30259ea"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "27dd61d4d9997738e63e813f8b8ea9d5cf1291eb02d20d1a2ad75ac8aa99459c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 24 83 7D 08 00 75 0A B8 9A FF FF FF E9 65 02 00 00 8B 45 08 89 45 FC 8B 4D FC 83 79 18 00 75 0A B8 9A FF FF FF E9 4C 02 00 00 8B 55 FC 83 7A 7C 00 74 0C 8B 45 08 50 E8 5F 06 00 }

	condition:
		all of them
}
