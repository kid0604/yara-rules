rule Windows_Generic_Threat_4578ee8c
{
	meta:
		author = "Elastic Security"
		id = "4578ee8c-9dfc-4fb2-b5dc-8f55b6ee26d0"
		fingerprint = "3a40e6e8f35c5c114b1b0175723d9403c357bba7170c4350194d40d4a2c94c61"
		creation_date = "2024-02-14"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "699fecdb0bf27994d67492dc480f4ba1320acdd75e5881afbc5f73c982453fed"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 73 65 72 2D 41 67 65 6E 74 3A 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 25 64 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 25 64 2E 31 3B 20 53 56 31 29 }

	condition:
		all of them
}
