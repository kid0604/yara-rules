rule Windows_Generic_MalCert_599b3a08
{
	meta:
		author = "Elastic Security"
		id = "599b3a08-264e-4b9f-bfaf-73564de051bc"
		fingerprint = "633b264883a6bfbfac9c226b46e453ebac2881c922853194f64ba7c0e232f42d"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "5a1b32b077d39a9bfae88dca7a9e75be5a1e6ace2d3ecb8fc259fdae67d848a1"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 2D B9 F8 38 04 C0 78 54 A7 5A B0 8A }

	condition:
		all of them
}
