rule Windows_Generic_Threat_0e8530f5
{
	meta:
		author = "Elastic Security"
		id = "0e8530f5-32ce-48a2-9413-5a8f4596ba12"
		fingerprint = "33007c3793c74aaac45434cbd0b524973073a7223d68fae8da5cbd7296120739"
		creation_date = "2024-02-14"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9f44d9acf79ed4450195223a9da185c0b0e8a8ea661d365a3ddea38f2732e2b8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 63 6D 64 20 2F 63 20 73 74 61 72 74 20 22 22 20 22 25 53 25 53 22 20 25 53 }
		$a2 = { 76 68 61 50 20 71 20 65 71 30 75 61 }

	condition:
		all of them
}
