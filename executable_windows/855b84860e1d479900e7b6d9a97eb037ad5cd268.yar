rule Windows_Generic_Threat_dbe41439
{
	meta:
		author = "Elastic Security"
		id = "dbe41439-982d-4897-9007-9ad0f206dc75"
		fingerprint = "f7c94f5bc3897c4741899e4f6d2731cd07f61e593500efdd33b5d84693465dd3"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "64afd2bc6cec17402473a29b94325ae2e26989caf5a8b916dc21952149d71b00"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 E4 F8 83 EC 2C 53 56 8B F1 57 89 74 24 10 8B 46 1C 8B 08 85 C9 74 23 8B 56 2C 8B 3A 8D 04 0F 3B C8 73 17 8D 47 FF 89 02 8B 4E 1C 8B 11 8D 42 01 89 01 0F B6 02 E9 F1 00 00 00 33 DB }

	condition:
		all of them
}
