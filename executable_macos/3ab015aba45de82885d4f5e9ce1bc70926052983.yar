rule MacOS_Trojan_Bundlore_17b564b4
{
	meta:
		author = "Elastic Security"
		id = "17b564b4-7452-473f-873f-f907b5b8ebc4"
		fingerprint = "7701fab23d59b8c0db381a1140c4e350e2ce24b8114adbdbf3c382c6d82ea531"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore variant 17b564b4"
		filetype = "executable"

	strings:
		$a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }

	condition:
		all of them
}
