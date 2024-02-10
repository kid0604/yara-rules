rule Windows_Generic_Threat_fcab7e76
{
	meta:
		author = "Elastic Security"
		id = "fcab7e76-5edd-4485-9983-bcc5e9cb0a08"
		fingerprint = "8a01a3a398cfaa00c1b194b2abc5a0c79d21010abf27dffe5eb8fdc602db7ad1"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "67d7e016e401bd5d435eecaa9e8ead341aed2f373a1179069f53b64bda3f1f56"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 FA 00 2B CD 65 50 7C FF CF 34 00 80 41 BF 1E 12 1A F9 20 0F 56 EE 9F BA C0 22 7E 97 FC CB 03 C7 67 9A AE 8A 60 C0 B3 6C 0D 00 2B 2C 78 83 B5 88 03 17 3A 51 4A 1F 30 D2 C0 53 DC 09 7A BF 2D }

	condition:
		all of them
}
