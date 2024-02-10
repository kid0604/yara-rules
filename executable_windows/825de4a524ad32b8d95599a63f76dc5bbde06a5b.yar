rule Windows_Generic_Threat_0a38c7d0
{
	meta:
		author = "Elastic Security"
		id = "0a38c7d0-8f5e-4dcf-9aaf-5fcf96451d3c"
		fingerprint = "43998ceb361ecf98d923c0388c00023f19d249a5ac0011dee0924fdff92af42b"
		creation_date = "2024-01-22"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "69ea7d2ea3ed6826ddcefb3c1daa63d8ab53dc6e66c59cf5c2506a8af1c62ef4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 8B 4D 08 85 C9 74 37 8B 45 0C 3D E0 10 00 00 7C 05 B8 E0 10 00 00 85 C0 7E 24 8D 50 FF B8 AB AA AA AA F7 E2 D1 EA 83 C1 02 42 53 8B FF 8A 41 FE 8A 19 88 59 FE 88 01 83 C1 03 4A 75 F0 }

	condition:
		all of them
}
