rule Linux_Trojan_Tsunami_35806adc
{
	meta:
		author = "Elastic Security"
		id = "35806adc-9bac-4481-80c8-a673730d5179"
		fingerprint = "f0b4686087ddda1070b62ade7ad7eb69d712e15f5645aaba24c0f5b124a283ac"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "15e7942ebf88a51346d3a5975bb1c2d87996799e6255db9e92aed798d279b36b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 85 3C 93 48 1F 03 36 84 C0 4B 28 7F 18 86 13 08 10 1F EC B0 73 }

	condition:
		all of them
}
