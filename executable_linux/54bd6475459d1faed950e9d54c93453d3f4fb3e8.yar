rule Linux_Trojan_Psybnc_f07357f1
{
	meta:
		author = "Elastic Security"
		id = "f07357f1-1a92-4bd7-a43d-7a75fb90ac83"
		fingerprint = "f0f1008fec444ce25d80f9878a04d9ebe9a76f792f4be8747292ee7b133ea05c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Psybnc"
		reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Psybnc"
		filetype = "executable"

	strings:
		$a = { F7 EA 89 D0 C1 F8 02 89 CF C1 FF 1F 29 F8 8D 04 80 01 C0 29 C1 8D }

	condition:
		all of them
}
