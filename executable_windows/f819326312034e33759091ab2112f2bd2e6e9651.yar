rule Windows_Generic_Threat_baba80fb
{
	meta:
		author = "Elastic Security"
		id = "baba80fb-1d8a-424c-98e2-904c8f2e4f09"
		fingerprint = "71d9345d0288bfbbf7305962e5e316801d4a5cba332c5f4167f8e4f39cff6f61"
		creation_date = "2024-01-24"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "dd22cb2318d66fa30702368a7f06e445fba4b69daf9c45f8e83562d2c170a073"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 0C 8B 4D 0C 53 56 57 8B 59 20 8D 71 20 8B F9 89 75 FC 85 DB 89 7D 0C 75 05 8B 59 24 EB 0C 8D 41 24 89 45 F8 8B 00 85 C0 75 30 8B 51 28 8B 41 2C 85 DB 74 03 89 53 28 85 D2 74 15 }

	condition:
		all of them
}
