rule Linux_Trojan_Mirai_5946f41b
{
	meta:
		author = "Elastic Security"
		id = "5946f41b-594c-4fde-827c-616a99f6fc1b"
		fingerprint = "f28b9b311296fc587eced94ca0d80fc60ee22344e5c38520ab161d9f1273e328"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "f0b6bf8a683f8692973ea8291129c9764269a6739650ec3f9ee50d222df0a38a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 5946f41b"
		filetype = "executable"

	strings:
		$a = { 59 08 AA 3A 4C D3 6C 2E 6E F7 24 54 32 7C 61 39 65 21 66 74 }

	condition:
		all of them
}
