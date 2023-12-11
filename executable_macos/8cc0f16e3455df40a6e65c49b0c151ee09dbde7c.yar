rule MacOS_Trojan_Bundlore_c90c088a
{
	meta:
		author = "Elastic Security"
		id = "c90c088a-abf5-4e52-a69e-5a4fd4b5cf15"
		fingerprint = "c2300895f8ff5ae13bc0ed93653afc69b30d1d01f5ce882bd20f2b65426ecb47"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore malware"
		filetype = "executable"

	strings:
		$a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }

	condition:
		all of them
}
