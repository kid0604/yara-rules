rule Linux_Trojan_Mirai_dca3b9b4
{
	meta:
		author = "Elastic Security"
		id = "dca3b9b4-62f3-41ed-a3b3-80dd0990f8c5"
		fingerprint = "b0471831229be1bcbcf6834e2d1a5b85ed66fb612868c2c207fe009ae2a0e799"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "a839437deba6d30e7a22104561e38f60776729199a96a71da3a88a7c7990246a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint dca3b9b4"
		filetype = "executable"

	strings:
		$a = { 83 45 F4 01 8B 45 F4 3B 45 F0 75 11 48 8B 45 F8 48 2B 45 D8 }

	condition:
		all of them
}
