rule Windows_Generic_Threat_89efd1b4
{
	meta:
		author = "Elastic Security"
		id = "89efd1b4-9a4b-4749-8b34-630883d2d45b"
		fingerprint = "659bdc9af01212de3d2492e0805e801b0a00630bd699360be15d3fe5b221f6b3"
		creation_date = "2024-01-11"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "937c8bc3c89bb9c05b2cb859c4bf0f47020917a309bbadca36236434c8cdc8b9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC E0 01 00 00 48 89 9C 24 F8 01 00 00 48 83 F9 42 0F 85 03 01 00 00 48 89 84 24 F0 01 00 00 48 89 9C 24 F8 01 00 00 44 0F 11 BC 24 88 01 00 00 44 0F 11 BC 24 90 01 00 00 44 0F 11 BC 24 }

	condition:
		all of them
}
