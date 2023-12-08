rule MacOS_Trojan_Adload_f6b18a0a
{
	meta:
		author = "Elastic Security"
		id = "f6b18a0a-7593-430f-904b-8d416861d165"
		fingerprint = "f33275481b0bf4f4e57c7ad757f1e22d35742fc3d0ffa3983321f03170b5100e"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Adload"
		reference_sample = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Adload with fingerprint f6b18a0a"
		filetype = "executable"

	strings:
		$a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }

	condition:
		all of them
}
