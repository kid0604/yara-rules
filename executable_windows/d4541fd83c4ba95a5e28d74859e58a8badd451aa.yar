rule Windows_Generic_MalCert_a8d852d0
{
	meta:
		author = "Elastic Security"
		id = "a8d852d0-5fda-4a82-8eb7-5363e44f4fbb"
		fingerprint = "be9cfa1d71fc603e0918a7acfba1b1114bfb1a4c1b717da246722de216762cda"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "ce7dfe11133790e7d123fd7ae1bf7412868f045cbe4a0631a2c7b5ba7225113b"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 30 EE 7D 2A 15 85 FA CB E9 3A 8F 0E F8 60 F4 6F }

	condition:
		all of them
}
