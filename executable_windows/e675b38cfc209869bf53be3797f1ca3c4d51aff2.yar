rule Windows_Generic_Threat_d542e5a5
{
	meta:
		author = "Elastic Security"
		id = "d542e5a5-0648-40de-8b70-9f78f9bd1443"
		fingerprint = "62d3edc282cedd5a6464b92725a3916e3bdc75e8eb39db457d783cb27afa3aec"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "3fc4ae7115e0bfa3fc6b75dcff867e7bf9ade9c7f558f31916359d37d001901b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 56 FF 75 08 8B F1 E8 B6 FF FF FF C7 06 AC 67 41 00 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 FF 75 08 8B F1 E8 99 FF FF FF C7 06 B8 67 41 00 8B C6 5E 5D C2 04 00 B8 EF 5B 40 00 A3 E8 5A }

	condition:
		all of them
}
