rule Linux_Trojan_Mobidash_e2c89606
{
	meta:
		author = "Elastic Security"
		id = "e2c89606-511c-403a-a4eb-d18dc7aca444"
		fingerprint = "91c51f6af18389f2efb0032e0b775df68f34b66795c05623dccb67266c04214b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { 13 49 89 C7 4C 89 E6 48 89 DF FF 92 B8 00 00 00 31 C9 4C 89 FA 4C }

	condition:
		all of them
}
