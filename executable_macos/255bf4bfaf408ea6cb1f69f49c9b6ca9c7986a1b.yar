rule MacOS_Trojan_Bundlore_cb7344eb
{
	meta:
		author = "Elastic Security"
		id = "cb7344eb-51e6-4f17-a5d4-eea98938945b"
		fingerprint = "6041c50c9eefe9cafb8768141cd7692540f6af2cdd6e0a763b7d7e50b8586999"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Bundlore"
		filetype = "executable"

	strings:
		$a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }

	condition:
		all of them
}
