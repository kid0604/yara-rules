rule Linux_Trojan_Mirai_d5da717f
{
	meta:
		author = "Elastic Security"
		id = "d5da717f-3344-41a8-884e-8944172ea370"
		fingerprint = "c3674075a435ef1cd9e568486daa2960450aa7ffa8e5dbf440a50e01803ea2f3"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 00 00 66 83 7C 24 34 FF 66 89 46 2C 0F 85 C2 }

	condition:
		all of them
}
