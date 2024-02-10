rule Windows_Generic_Threat_dc4ede3b
{
	meta:
		author = "Elastic Security"
		id = "dc4ede3b-d0c7-4993-8629-88753d65a7ad"
		fingerprint = "8be5afdf2a5fe5cb1d4b50d10e8e2e8e588a72d6c644aa1013dd293c484da33b"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c49f20c5b42c6d813e6364b1fcb68c1b63a2f7def85a3ddfc4e664c4e90f8798"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 83 EC 28 C7 45 FC 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 10 03 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 04 00 00 00 80 8B 45 08 }

	condition:
		all of them
}
