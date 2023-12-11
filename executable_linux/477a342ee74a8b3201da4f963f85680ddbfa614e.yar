rule Linux_Exploit_CVE_2009_2698_cc04dddd
{
	meta:
		author = "Elastic Security"
		id = "cc04dddd-91d0-4c5f-a0ac-01787da7f369"
		fingerprint = "d3fdd66e486cb06bd63f6d8e471e66bc80990c4f0729eea16b47adc4cac80538"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2009-2698"
		reference_sample = "502b73ea04095e8a7ec4e8d7cc306242b45850ad28690156754beac8cd8d7b2d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2009-2698"
		filetype = "executable"

	strings:
		$a = { C4 10 89 45 F4 83 7D F4 FF 75 1F 83 EC 0C 68 }

	condition:
		all of them
}
