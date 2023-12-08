rule MacOS_Trojan_Genieo_5e0f8980
{
	meta:
		author = "Elastic Security"
		id = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
		fingerprint = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Genieo"
		reference_sample = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Genieo"
		filetype = "executable"

	strings:
		$a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }

	condition:
		all of them
}
