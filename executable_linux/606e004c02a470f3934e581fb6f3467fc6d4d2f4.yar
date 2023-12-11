rule Linux_Trojan_Kinsing_7cdbe9fa
{
	meta:
		author = "Elastic Security"
		id = "7cdbe9fa-39a3-43a0-853a-16f41e20f304"
		fingerprint = "2452c2821b4ca104a18d3733ee8f6744a738aca197aa35392c480e224a5f8175"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Kinsing"
		reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kinsing"
		filetype = "executable"

	strings:
		$a = { 73 2E 72 75 22 20 7C 20 61 77 6B 20 27 7B 70 72 69 6E 74 20 }

	condition:
		all of them
}
