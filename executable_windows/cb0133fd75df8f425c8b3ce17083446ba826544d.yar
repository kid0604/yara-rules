rule Windows_Trojan_JesterStealer_8f657f58
{
	meta:
		author = "Elastic Security"
		id = "8f657f58-57e0-4e5f-9223-00bfade16605"
		fingerprint = "aabf8633e853f623b75e8a354378d110442e724425f623b8c553d3522ca5dad6"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.JesterStealer"
		reference_sample = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan JesterStealer"
		filetype = "executable"

	strings:
		$a1 = { 27 01 00 00 00 96 08 0B 80 79 01 6C 02 A4 27 01 00 00 00 96 08 }

	condition:
		all of them
}
