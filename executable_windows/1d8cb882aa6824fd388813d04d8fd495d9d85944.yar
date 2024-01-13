rule Windows_Generic_Threat_a1cef0cd
{
	meta:
		author = "Elastic Security"
		id = "a1cef0cd-a811-4d7b-b24e-7935c0418c7a"
		fingerprint = "9285f0ea8ed0ceded2f3876ef197b67e8087f7de82a72e0cd9899b05015eee79"
		creation_date = "2024-01-08"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "71f519c6bd598e17e1298d247a4ad37b78685ca6fd423d560d397d34d16b7db8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 8B DA 89 45 FC 8B 45 FC E8 76 00 00 00 33 C0 55 68 F0 A0 41 00 64 FF 30 64 89 20 8B 45 FC 80 78 20 01 74 10 8B 45 FC 8B 40 04 8B D3 E8 CE FC FF FF 40 75 0F 8B 45 FC 8B 40 04 8B }

	condition:
		all of them
}
