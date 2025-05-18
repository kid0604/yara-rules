rule Windows_Generic_MalCert_1dac3f8f
{
	meta:
		author = "Elastic Security"
		id = "1dac3f8f-bb36-411f-883e-57db1e6153cc"
		fingerprint = "0b29ddfe316ddc3d6792d4447a36f307e37c4bb8ee6cab5a7afb30d1cdacf74c"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "5569d9ed0aaaf546f56f2ffc5b6e1ec8f7c2ec7be311477b64cc9062bb4b95a4"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 C1 1E 1A A0 5B D7 47 EA B4 3F B3 1E B6 A5 31 DC }

	condition:
		all of them
}
