rule Windows_Generic_Threat_742e8a70
{
	meta:
		author = "Elastic Security"
		id = "742e8a70-c150-4903-a551-9123587dd473"
		fingerprint = "733b3563275da0a1b4781b9c0aa07e6e968133ae099eddef9cad3793334b9aa5"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "94f7678be47651aa457256375f3e4d362ae681a9524388c97dc9ed34ba881090"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC E8 96 FF FF FF E8 85 0D 00 00 83 7D 08 00 A3 A4 E9 43 00 74 05 E8 0C 0D 00 00 DB E2 5D C3 8B FF 55 8B EC 83 3D B0 E9 43 00 02 74 05 E8 BA 12 00 00 FF 75 08 E8 07 11 00 00 68 FF 00 00 }

	condition:
		all of them
}
