rule Windows_Generic_Threat_779cf969
{
	meta:
		author = "Elastic Security"
		id = "779cf969-d1a0-4280-94cb-c7f62d33482c"
		fingerprint = "7e089462cc02e2c9861018df71bf5dda6a3a982d3d98b252d44387c937526be4"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ef281230c248442c804f1930caba48f0ae6cef110665020139f826ab99bbf274"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 3E 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 50 79 74 68 6F 6E 20 53 6F 66 74 77 61 72 65 20 46 6F 75 6E 64 61 74 69 6F 6E 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E }

	condition:
		all of them
}
