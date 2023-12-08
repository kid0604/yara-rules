rule Linux_Trojan_Mirai_d5981806
{
	meta:
		author = "Elastic Security"
		id = "d5981806-0db8-4422-ad57-5d1c0f7464c3"
		fingerprint = "b0fd8632505252315ba551bb3680fa8dc51038be17609018bf9d92c3e1c43ede"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "784f2005853b5375efaf3995208e4611b81b8c52f67b6dc139fd9fec7b49d9dc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 3F 00 00 66 83 7C 24 38 FF 66 89 46 04 0F 85 EA }

	condition:
		all of them
}
