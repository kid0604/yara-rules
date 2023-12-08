rule Linux_Trojan_Swrort_4cb5b116
{
	meta:
		author = "Elastic Security"
		id = "4cb5b116-5e90-4e5f-a62f-bfe616cab5db"
		fingerprint = "cb783f69b4074264a75894dd85459529a172404a6901a1f5753a2f9197bfca58"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Swrort"
		reference_sample = "703c16d4fcc6f815f540d50d8408ea00b4cf8060cc5f6f3ba21be047e32758e0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Swrort"
		filetype = "executable"

	strings:
		$a = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 04 6A 10 89 E1 6A 00 }

	condition:
		all of them
}
