rule Linux_Trojan_Xorddos_ebce4304
{
	meta:
		author = "Elastic Security"
		id = "ebce4304-0a06-454f-ad08-98b323e5b23a"
		fingerprint = "20f0346bf021e3d2a0e25bbb3ed5b9c0a45798d0d5b2516b679f7bf17d1b040d"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos (ebce4304)"
		filetype = "executable"

	strings:
		$a = { 24 8D 64 24 04 87 54 24 00 56 8B 74 24 04 5E 9D 9C 83 C5 1E 9D 8D }

	condition:
		all of them
}
