rule Windows_Generic_MalCert_0c9007f3
{
	meta:
		author = "Elastic Security"
		id = "0c9007f3-e70c-4fda-b00d-3606b3ed9e5f"
		fingerprint = "2805811562cd1fa87d4dd5e0a65f92bf3f7404e0487f8b6abe56e8a3674296c4"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "e4fcfb24360d755e8d4ba198780eed06c0ae94bec415e034d121ac7980d1f6a4"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 01 C7 B2 3C FC 00 7A 6C A9 4A BD 7D B7 5E BC 5D }

	condition:
		all of them
}
