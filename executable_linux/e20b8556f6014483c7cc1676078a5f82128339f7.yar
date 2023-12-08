rule Linux_Trojan_Mobidash_d0ad9c82
{
	meta:
		author = "Elastic Security"
		id = "d0ad9c82-718f-43d1-a764-9be83893f9b8"
		fingerprint = "ef6b2f9383c137eb4adfe0a6322a0e5d71cb4a5712f1be26fe687144933cbbc8"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Mobidash (d0ad9c82)"
		filetype = "executable"

	strings:
		$a = { 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 8D 64 24 F8 48 8B 07 FF 90 F8 00 }

	condition:
		all of them
}
