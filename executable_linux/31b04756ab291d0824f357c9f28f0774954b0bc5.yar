rule Linux_Trojan_Sshdoor_1b443a9b
{
	meta:
		author = "Elastic Security"
		id = "1b443a9b-2bd2-4b63-baaa-d66ca43ba521"
		fingerprint = "ff44d7b3c8db5cd0d12a99c2aafb1831f63c6253fe0e63fb7d2503bc74e6fca9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "a33112daa5a7d31ea1a1ca9b910475843b7d8c84d4658ccc00bafee044382709"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor with fingerprint 1b443a9b"
		filetype = "executable"

	strings:
		$a = { 24 10 44 39 F8 7F B4 3B 44 24 04 7C AE 3B 44 24 0C 7E 10 41 }

	condition:
		all of them
}
