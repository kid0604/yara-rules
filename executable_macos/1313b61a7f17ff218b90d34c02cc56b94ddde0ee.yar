rule MacOS_Trojan_Bundlore_c8ad7edd
{
	meta:
		author = "Elastic Security"
		id = "c8ad7edd-4233-44ce-a4e5-96dfc3504f8a"
		fingerprint = "c6a8a1d9951863d4277d297dd6ff8ad7b758ca2dfe16740265456bb7bb0fd7d0"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore malware"
		filetype = "executable"

	strings:
		$a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }

	condition:
		all of them
}
