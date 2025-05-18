rule Windows_Generic_MalCert_8d94d2bb
{
	meta:
		author = "Elastic Security"
		id = "8d94d2bb-5ee1-4aa0-bae5-c5d91180a08c"
		fingerprint = "e41f27f4ca41b49d8dca2beb3b3eba6d7fa173e574d7a74b7f20801c383a4a8a"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "7250c63c0035065eeae6757854fa2ac3357bab9672c93b77672abf7b6f45920a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 49 7E 77 B2 0D 07 E6 37 B1 3B BA 63 54 BB 86 CF }

	condition:
		all of them
}
