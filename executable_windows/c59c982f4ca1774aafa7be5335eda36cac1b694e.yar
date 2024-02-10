rule Windows_Generic_Threat_eab96cf2
{
	meta:
		author = "Elastic Security"
		id = "eab96cf2-f25a-4149-9328-3f7af50b2ad8"
		fingerprint = "a07bbc803aa7ae54d0c0b2b15edf8378646f06906151998ac3d5491245813dd9"
		creation_date = "2024-01-11"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2be8a2c524f1fb2acb2af92bc56eb9377c4e16923a06f5ac2373811041ea7982"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 41 52 FF E0 58 41 59 5A 48 8B 12 E9 4B FF FF FF 5D 48 31 DB 53 49 BE 77 69 6E 68 74 74 70 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 53 53 48 89 E1 53 5A 4D 31 C0 4D 31 C9 53 53 }

	condition:
		all of them
}
