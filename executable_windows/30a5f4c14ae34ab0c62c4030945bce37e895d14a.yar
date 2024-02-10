rule Windows_Generic_Threat_6542ebda
{
	meta:
		author = "Elastic Security"
		id = "6542ebda-c91e-449e-88c4-244fba69a4b2"
		fingerprint = "a4ceaf0bf2e8dc3efbc6e41e608816385f40c04984659b0ec15f109b7a6bf20a"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2073e51c7db7040c6046e36585873a0addc2bcddeb6e944b46f96c607dd83595"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 53 56 57 8B F9 85 D2 74 18 0F B7 02 8D 5A 02 0F B7 72 02 8B 4A 04 3B C7 74 0E 83 C2 08 03 D1 75 E8 33 C0 5F 5E 5B 5D C3 B8 78 03 00 00 66 3B F0 74 EF 8B 45 08 89 18 8D 41 06 EB E7 8D }

	condition:
		all of them
}
