rule Windows_Generic_MalCert_81098b3c
{
	meta:
		author = "Elastic Security"
		id = "81098b3c-aba7-4838-be76-0eb632c7ae1e"
		fingerprint = "d4a67c7f5209e243acc72b5e6baf06b5aa174aa1fe90109941df1c3a9b892ffd"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "dc2358df8e7562b826da179aad111f0fdd461a56470f1bb3c72b25c53c164751"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 11 7E 18 46 AC 13 0D C4 FA 8F 3E 17 9B 5F A3 C9 }

	condition:
		all of them
}
