rule Linux_Trojan_Generic_d8953ca0
{
	meta:
		author = "Elastic Security"
		id = "d8953ca0-f1f1-4d76-8c80-06f16998ba03"
		fingerprint = "16ab55f99be8ed2a47618978a335a8c68369563c0a4d0a7ff716b5d4c9e0785c"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "552753661c3cc7b3a4326721789808482a4591cb662bc813ee50d95f101a3501"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with fingerprint d8953ca0"
		filetype = "executable"

	strings:
		$a = { 5B 9C 9C 9C 9C 5C 5D 5E 5F 9C 9C 9C 9C B1 B2 B3 B4 9C 9C 9C 9C }

	condition:
		all of them
}
