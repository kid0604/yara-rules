rule Windows_Generic_Threat_fac6d993
{
	meta:
		author = "Elastic Security"
		id = "fac6d993-a9c5-4218-829d-d0f3a3b9a5a0"
		fingerprint = "7502d32cf94496b73e476c7521b84a40426676b335a86bdf1bce7146934efcee"
		creation_date = "2024-01-03"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "f3e7c88e72cf0c1f4cbee588972fc1434065f7cc9bd95d52379bade1b8520278"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 E4 F8 81 EC 4C 04 00 00 53 8B D9 8B 4D 2C 33 C0 89 01 8B 4D 30 56 0F B6 B3 85 00 00 00 89 01 8B 4D 34 57 0F B6 BB 84 00 00 00 89 01 8B 4D 38 89 54 24 10 89 01 8D 44 24 48 50 FF 15 }

	condition:
		all of them
}
