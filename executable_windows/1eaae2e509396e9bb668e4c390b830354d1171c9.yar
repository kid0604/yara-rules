rule Windows_Trojan_Deimos_c70677b4
{
	meta:
		author = "Elastic Security"
		id = "c70677b4-f5ba-440b-ba31-31e80caee2fe"
		fingerprint = "ffe0dec3585da9cbb9f8a0fac1bb6fd43d5d6e20a6175aaa889ae13ef2ed101f"
		creation_date = "2021-09-18"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Deimos"
		reference_sample = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Deimos"
		filetype = "executable"

	strings:
		$a1 = { 00 57 00 58 00 59 00 5A 00 5F 00 00 17 75 00 73 00 65 00 72 00 }
		$a2 = { 0C 08 16 1F 68 9D 08 17 1F 77 9D 08 18 1F 69 9D 08 19 1F 64 9D }

	condition:
		1 of ($a*)
}
