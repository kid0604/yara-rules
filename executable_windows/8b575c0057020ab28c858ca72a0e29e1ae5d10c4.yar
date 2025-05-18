rule Windows_Generic_MalCert_6606e2be
{
	meta:
		author = "Elastic Security"
		id = "6606e2be-4503-4f52-b2b6-0b7e190acc8e"
		fingerprint = "4f95a8af6dc00c731c2f64e6030d6e86169963a8fa969d8dd7d7574b91733068"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "c1fa31b49157e684fb05494dcf0db72d0133c1d433cb64dc8f6914343f1e6d98"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert threat"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 83 23 A1 C8 0A 83 EA 88 6F C3 58 08 97 90 39 F7 }

	condition:
		all of them
}
