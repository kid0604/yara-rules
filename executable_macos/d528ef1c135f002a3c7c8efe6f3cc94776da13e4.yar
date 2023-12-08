rule MacOS_Trojan_Bundlore_753e5738
{
	meta:
		author = "Elastic Security"
		id = "753e5738-0c72-4178-9396-d1950e868104"
		fingerprint = "c0a41a8bc7fbf994d3f5a5d6c836db3596b1401b0e209a081354af2190fcb3c2"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore variant 753e5738"
		filetype = "executable"

	strings:
		$a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }

	condition:
		all of them
}
